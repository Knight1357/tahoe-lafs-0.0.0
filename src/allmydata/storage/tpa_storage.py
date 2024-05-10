# -*- coding: utf-8 -*-
import json
import logging
import os
import struct
import threading
import time
import gmpy2
from twisted.application import service
from twisted.internet import protocol
from allmydata.interfaces import SDMF_VERSION, MDMF_VERSION, SALT_SIZE
from allmydata.mutable.common import UnknownVersionError, BadShareError
from allmydata.mutable.layout import (
    SIGNED_PREFIX_LENGTH,
    MDMFHEADERWITHOUTOFFSETS,
    MDMFHEADERWITHOUTOFFSETSSIZE,
    OFFSETS_LENGTH,
    MDMFOFFSETS_LENGTH,
    MDMFOFFSETS,
    LayoutInvalid,
)
from allmydata.pdp import response_challenge_seq, Pdp
from allmydata.storage.common import storage_index_to_checkcode_dir
from allmydata.storage.immutable import BucketReader, ImCheckcodeFile
from allmydata.storage.mutable import MutableCheckcodeFile, MutableShareFile
from allmydata.storage.server import NUM_RE
from allmydata.util import mathutil, pdputil, base32
from allmydata.util.assertutil import precondition
from allmydata.util.base32 import a2b


class Tpa(protocol.Protocol, service.MultiService):
    def __init__(self, ss):
        service.MultiService.__init__(self)
        self.recv_len = 0
        self.byte_buffer = b""
        self.data_len = 0
        self.ss = ss
        self.version = "immutable"
        self.pdp = Pdp()
        
    def dataReceived(self, data):
        t = threading.Thread(target=self.process_request, args=(data,))
        t.start()

    # 处理数据
    def process_request(self, data):
        if not data:
            self.transport.loseConnection()
        else:
            if not self.data_len:
                lenbyte = data[:8]
                data = data[8:]
                self.data_len = struct.unpack("Q", lenbyte)[0]
                # print("数据长度为 {}".format(self.data_len))
            if self.recv_len + len(data) >= self.data_len:
                self.byte_buffer += data
                self.recv_len += len(data)
                # print("共接收到数据长度为 {}".format(self.recv_len))
                self.transport.write(self.run(self.byte_buffer))
                self.transport.loseConnection()
            else:
                self.byte_buffer += data
                self.recv_len += len(data)

    # TCP断开连接
    def connectionLost(self, reason=protocol.connectionDone):
        logging.debug("连接断开：{}".format(reason))

    # 响应挑战序列，返回校验结果
    def run(self, data):
        data = a2b(data).decode('utf-8')
        data = json.loads(data)
        (iis, vis) = self.pre_parse(data)
        if self.version == "mutable":
            (u, q) = self.mutable_start(iis, vis)
        else:
            (u, q) = self.immutable_start(iis, vis)
        challenge_result = {"u": hex(u), "q": hex(q)}

        return json.dumps(challenge_result).encode("utf-8")

    # 解析mutabled的offset
    def maybe_fetch_offsets_and_header(self, msf):
        readvs = [(0, 123)]
        datav = msf.readv(readvs)
        ep = self._process_encoding_parameters(datav)
        self._process_offsets(ep)

    # 处理offset解析异常
    def _handle_bad_struct(f):
        # struct.unpack errors mean the server didn't give us enough data, so
        # this share is bad
        f.trap(struct.error)
        raise BadShareError(f.value.args[0])

    def _process_encoding_parameters(self, encoding_parameters):
        encoding_parameters = encoding_parameters[0]
        (verno,) = struct.unpack(">B", encoding_parameters[:1])
        if verno == MDMF_VERSION:
            read_size = MDMFHEADERWITHOUTOFFSETSSIZE
            (verno, seqnum, root_hash, k, n, segsize, datalen) = struct.unpack(
                MDMFHEADERWITHOUTOFFSETS, encoding_parameters[:read_size]
            )
            if segsize == 0 and datalen == 0:
                # Empty file, no segments.
                self._num_segments = 0
            else:
                self._num_segments = mathutil.div_ceil(datalen, segsize)
        elif verno == SDMF_VERSION:
            read_size = SIGNED_PREFIX_LENGTH
            (verno, seqnum, root_hash, salt, k, n, segsize, datalen) = struct.unpack(
                ">BQ32s16s BBQQ", encoding_parameters[:SIGNED_PREFIX_LENGTH]
            )
            self._salt = salt
            if segsize == 0 and datalen == 0:
                # empty file
                self._num_segments = 0
            else:
                # non-empty SDMF files have one segment.
                self._num_segments = 1
        else:
            raise UnknownVersionError(
                "You asked me to read mutable file "
                "version %d, but I only understand "
                "%d and %d" % (verno, SDMF_VERSION, MDMF_VERSION)
            )
        self._version_number = verno
        self._sequence_number = seqnum
        self._root_hash = root_hash
        self._required_shares = k
        self._total_shares = n
        self._segment_size = segsize
        self._data_length = datalen
        self._block_size = self._segment_size / self._required_shares
        if datalen > 0:
            tail_size = self._data_length % self._segment_size
        else:
            tail_size = 0
        if not tail_size:
            self._tail_block_size = self._block_size
        else:
            self._tail_block_size = mathutil.next_multiple(
                tail_size, self._required_shares
            )
            self._tail_block_size /= self._required_shares
        return encoding_parameters

    # 处理得到offsets
    def _process_offsets(self, offsets):
        if self._version_number == 0:
            read_size = OFFSETS_LENGTH
            read_offset = SIGNED_PREFIX_LENGTH
            end = read_size + read_offset
            (
                signature,
                share_hash_chain,
                block_hash_tree,
                share_data,
                enc_privkey,
                EOF,
            ) = struct.unpack(">LLLLQQ", offsets[read_offset:end])
            self._offsets = {}
            self._offsets["signature"] = signature
            self._offsets["share_data"] = share_data
            self._offsets["block_hash_tree"] = block_hash_tree
            self._offsets["share_hash_chain"] = share_hash_chain
            self._offsets["enc_privkey"] = enc_privkey
            self._offsets["EOF"] = EOF

        elif self._version_number == 1:
            read_offset = MDMFHEADERWITHOUTOFFSETSSIZE
            read_length = MDMFOFFSETS_LENGTH
            end = read_offset + read_length
            (
                encprivkey,
                sharehashes,
                signature,
                verification_key,
                verification_key_end,
                sharedata,
                blockhashes,
                eof,
            ) = struct.unpack(MDMFOFFSETS, offsets[read_offset:end])
            self._offsets = {}
            self._offsets["enc_privkey"] = encprivkey
            self._offsets["block_hash_tree"] = blockhashes
            self._offsets["share_hash_chain"] = sharehashes
            self._offsets["signature"] = signature
            self._offsets["verification_key"] = verification_key
            self._offsets["verification_key_end"] = verification_key_end
            self._offsets["EOF"] = eof
            self._offsets["share_data"] = sharedata

    # 读取 mutable share file 的第 segnum 个 block
    # 返回block内容
    def get_block_and_salt(self, msf, segnum):
        d = self._maybe_fetch_offsets_and_header()

        def _then(ignored):
            base_share_offset = self._offsets["share_data"]
            if segnum + 1 > self._num_segments:
                raise LayoutInvalid("Not a valid segment number")
            if self._version_number == 0:
                share_offset = base_share_offset + self._block_size * segnum
            else:
                share_offset = (
                    base_share_offset + (self._block_size + SALT_SIZE) * segnum
                )
            if segnum + 1 == self._num_segments:
                data = self._tail_block_size
            else:
                data = self._block_size

            if self._version_number == 1:
                data += SALT_SIZE

            readvs = [(share_offset, data)]
            return readvs

        d.addCallback(_then)
        d.addCallback(lambda readvs: msf.readv(readvs))

    
    def mutable_start(self, iis, vis):
        start = time.time()
        mcheckcode_readers = self.get_mutable_checkcode_readers(self.storage_index)
        mreader = self.get_mutable_readers(self.storage_index)
        challenge_blocks = []
        challenge_block_checkcodes = []
        for i in range(len(iis)):# challenge_blocks
            ii = iis[i]
            for sharenum, msf in mreader.items():
                challenge_block = self.get_mcb(msf, ii)
                challenge_block_mpz = pdputil.convert_bytes_to_mpz(challenge_block[0])
                challenge_blocks.append(challenge_block_mpz)
        for i in range(len(iis)):# challenge_block_checkcodes
            ii = iis[i]
            for sharenum, mcf in mcheckcode_readers.items():
                checkcode = self.get_checkcode(mcf, ii)
                checkcode_mpz = pdputil.convert_bytes_to_mpz(checkcode)
                challenge_block_checkcodes.append(checkcode_mpz)
        (u, q) = response_challenge_seq(
            iis, vis, challenge_blocks, challenge_block_checkcodes
        )
        end = time.time()
        logging.debug("mutbale file pdp time spend: {}".format(end - start))
        return (u, q)

    # 获取ii个challenge block内容
    def get_mcb(self, msf, ii):
        (i, j) = self.ii_to_block(ii)
        self.maybe_fetch_offsets_and_header(msf)

        def _then():
            base_share_offset = self._offsets["share_data"]
            if self._version_number == 0:
                share_offset = base_share_offset + self._block_size * i
            else:
                share_offset = base_share_offset + (self._block_size + SALT_SIZE) * i
            offset = share_offset + j * self.pdp.cblock_size + SALT_SIZE
            return [(offset, self.pdp.cblock_size)]

        data = msf.readv(_then())
        return data

    def immutable_start(self, iis, vis):
        """
        获取数据内容，进行校验
        @param iis: challenge block 索引列表
        @param vis: 对应的随机数列表
        @return: 返回校验结果
        """
        bucketreaders = self.get_immutable_bucketreaders()
        imcheckcode_readers = self.get_immutable_checkcode_readers(self.storage_index)
        challenge_blocks = []
        challenge_block_checkcodes = []
        for i in range(len(iis)):
            ii = iis[i]
            for sharenum, bucket in bucketreaders.items():
                challenge_block = self.get_imcb(bucket, ii)
                challenge_block_mpz = pdputil.convert_bytes_to_mpz(challenge_block)
                challenge_blocks.append(challenge_block_mpz)
        for i in range(len(iis)):
            ii = iis[i]
            for sharenum, icf in imcheckcode_readers.items():
                checkcode = self.get_checkcode(icf, ii)
                checkcode_mpz = pdputil.convert_bytes_to_mpz(checkcode)
                challenge_block_checkcodes.append(checkcode_mpz)
        (u, q) = response_challenge_seq(
            iis, vis, challenge_blocks, challenge_block_checkcodes
        )
        return u, q

    # 获取imcfile reader
    def get_immutable_checkcode_readers(self, storage_index):
        si_dir = storage_index_to_checkcode_dir(storage_index)
        checkcode_dir = os.path.join(self.ss.sharedir, si_dir)
        challenge_block_checkcodes = {}
        if os.path.isdir(checkcode_dir):
            for sharenum_s in os.listdir(checkcode_dir):
                try:
                    sharenum = int(sharenum_s)
                except ValueError:
                    continue
                if sharenum == self.shnum:
                    checkcode_filename = os.path.join(checkcode_dir, sharenum_s)
                    icf = self._init_imcheckcode_file(checkcode_filename)
                    challenge_block_checkcodes[sharenum] = icf
        return challenge_block_checkcodes

    def _init_imcheckcode_file(self, checkcode_filename):
        """
        初始化immutable认证符文件
        @param checkcode_filename:认证符文件名
        @return:immutable认证符文件
        """
        icf = ImCheckcodeFile(checkcode_filename)
        return icf

    # 获取mutable的认证符读取器
    # 参数：
    #     storage_index：存储索引
    # 返回值：
    #     block_checkcodes：mutable认证符文件列表
    def get_mutable_checkcode_readers(self, storage_index):
        si_dir = storage_index_to_checkcode_dir(storage_index)
        checkcode_dir = os.path.join(self.ss.sharedir, si_dir)
        block_checkcodes = {}
        if os.path.isdir(checkcode_dir):
            for sharenum_s in os.listdir(checkcode_dir):
                try:
                    sharenum = int(sharenum_s)
                except ValueError:
                    continue
                if sharenum == self.shnum:
                    checkcode_filename = os.path.join(checkcode_dir, sharenum_s)
                    mcf = self._init_mcheckcode_file(checkcode_filename)
                    block_checkcodes[sharenum] = mcf
        return block_checkcodes

    # 初始化mutable认证符文件
    # 参数：
    #     checkcode_filename：认证符文件名
    # 返回值：
    #     mcf：mutable认证符文件
    def _init_mcheckcode_file(self, checkcode_filename):
        mcf = MutableCheckcodeFile(checkcode_filename, self)
        return mcf

    # 获得bucket读取storage_index文件下的mutable文件
    def get_mutable_readers(self, storage_index):
        storagedir = os.path.join(self.ss.sharedir, storage_index[:2], storage_index)
        shares = {}
        if os.path.isdir(storagedir):
            for sharenum_s in os.listdir(storagedir):
                try:
                    sharenum = int(sharenum_s)
                except ValueError:
                    continue
                if sharenum == self.shnum:
                    filename = os.path.join(storagedir, sharenum_s)
                    msf = MutableShareFile(filename, self)
                    shares[sharenum] = msf
        return shares

    # 获得当前share文件第i个challenge block checkcode内容
    # 转换成mpz返回
    def get_checkcode(self, f, i):
        offset = i * self.pdp.ccode_size
        len = self.pdp.ccode_size
        return f.readv(offset, len)

    # share第ii个challenge block 转换成第bi个block中的第cj个challenge block
    # 对应的offset = (cj - 1) * cblock_size
    def ii_to_block(self, ii):
        bi = ii / self.num_challenge_block
        cj = ii % self.num_challenge_block
        return (bi, cj)

    # 1.得到对应storage_index文件下的所有share文件bucket
    # 2.对每个share文件内容调用_parse_immutable_share方法进行处理
    # 3.处理后的文件内容设置为self.challenge_blocks
    def get_immutable_bucketreaders(self):
        # 获得bucketreaders
        bucketreaders = self.get_bucket_readers(self.storage_index)
        return bucketreaders

    # 获取ii偏移值的challenge block
    def get_imcb(self, bucket, ii):
        header = bucket.read(0, 0x44)
        self._parse_ims_header(header)
        offset = self._offsets["data"] + ii * self.pdp.cblock_size
        return bucket.read(offset, self.pdp.cblock_size)

    # 通过bucket读取当前share文件的第blocknum个block内容
    def get_block_data(self, bucket, blocknum, blocksize, thisblocksize):
        offset = self._offsets["data"] + blocknum * blocksize
        data = bucket.read(offset, thisblocksize)
        return data

    # 解析share header部分得到文件信息
    def _parse_ims_header(self, data):
        self._offsets = {}
        (version,) = struct.unpack(">L", data[0:4])
        if version == 1:
            precondition(len(data) >= 0x24)
            x = 0x0C
            fieldsize = 0x4
            fieldstruct = ">L"
        else:
            precondition(len(data) >= 0x44)
            x = 0x14
            fieldsize = 0x8
            fieldstruct = ">Q"
        self._version = version
        self._fieldsize = fieldsize
        self._fieldstruct = fieldstruct
        for field in (
            "data",
            "plaintext_hash_tree",  # UNUSED
            "crypttext_hash_tree",
            "block_hashes",
            "share_hashes",
            "uri_extension",
        ):
            offset = struct.unpack(fieldstruct, data[x : x + fieldsize])[0]
            x += fieldsize
            self._offsets[field] = offset
        return self._offsets

    # 解析TCP传输的JSON数据，返回挑战序列
    # 目前来看只需要传递storage_index就可以了
    def pre_parse(self, data):
        self.shnum = data["shnum"]
        self.version = data["version"]
        share_details = data["share_detail"]
        share_size = share_details["block_size"]
        self.block_size = share_details["block_size"]
        self.storage_index = share_details["storage_index"]
        self.num_challenge_block = self.block_size / self.pdp.cblock_size
        iis = data["iis"]
        vis = data["vis"]
        vis = [gmpy2.mpz(v, 16) for v in vis]
        return (iis, vis)

    # 1.获取对应storage_index下的所有immutable share文件的bucketreader
    def get_bucket_readers(self, storage_index):
        bucketreaders = {}  # k: sharenum, v: BucketReader
        for shnum, filename in self._get_bucket_share(storage_index):
            if shnum == self.shnum:
                bucketreaders[shnum] = BucketReader(
                    self.ss, filename, storage_index, shnum
                )
        return bucketreaders

    """
        @author: xxx
        @function:_get_bucket_share
            1.获取对应storage_index下的所有immutable share文件
            2.返回（f,filename）
                f:是share文件的编号
                filename:share文件的绝对路径
    """

    def _get_bucket_share(self, storage_index):
        storagedir = os.path.join(self.ss.sharedir, storage_index[:2], storage_index)
        try:
            for f in os.listdir(storagedir):
                if NUM_RE.match(f):
                    filename = os.path.join(storagedir, f)
                    yield (int(f), filename)
        except OSError:
            pass




class MutableTpa():
    def __init__(self):
        """

        """


class ImmutableTpa():
    def __init__(self):
        """

        """

# Tpa的工厂类，针对每个TCP连接创建Tpa实例
class TpaFactory(protocol.Factory):

    def __init__(self, ss):
        # 获取存储share文件夹
        self.ss = ss

    def buildProtocol(self, addr):
        return Tpa(self.ss)
