import hashlib
import socket
import struct
import random
import json
import threading

import gmpy2
import time

from allmydata.immutable.ethfactory import EthWorker
from allmydata.util import pdputil, base32
from allmydata.util.base32 import b2a


# 生成随机种子
def get_rand_state():
    r_state = gmpy2.random_state(int(time.time()))
    return r_state


# 返回cnt位的随机数
# 大小为 0~2^{n-1}
def get_randomb_num(r_state, cnt):
    # gmpy2.mpz_urandomb(random_state, bit_count, /)→ mpz
    # Return uniformly distributed random integer between 0 and 2**bit_count-1.
    random_num = gmpy2.mpz_urandomb(r_state, cnt)
    return random_num


def get_randomm_num(r_state, cnt):
    # gmpy2.mpz_random(random_state, int, /)→ mpz
    # Return uniformly distributed random integer between 0 and n-1.
    random_num = gmpy2.mpz_random(r_state, cnt)
    return random_num


# 返回cnt位的素数
def get_randomb_pnum(r_state, cnt):
    random_num = gmpy2.mpz_urandomb(r_state, cnt)
    random_pnum = gmpy2.next_prime(random_num)
    return random_pnum





class TpaClient:
    def __init__(self):
        self.N = 0
        self.r_state = get_rand_state()
        # p,g are fixed large prime numbers, consistent with the storage end nodes.
        self.G = gmpy2.mpz(
            "8744930370936677675691572579627854348401591927865428209403276589124198778726853734619578370823207519321616080054674049209442452175828495599202899292300093")
        self.P = gmpy2.mpz(
            "2630373295987918856248717725661016679397663965838488940293176904082486592825725810999021962983421413017941758493846955484028971753362061491943145531337277")
        self.A = None
        self.K = None
        self.eth = EthWorker()

    def start(self, data):
        self._parse(data)
        (vis, iis) = self._get_challenge_seq()
        result = True
        for shnum, addr in self.shares.items():
            ip, port = addr.split(":")
            result &= self._send_challenge(vis, iis, shnum, ip, int(port))
            # return result
            t = threading.Thread(target=self._send_challenge, args=(vis, iis, shnum, ip, port))
            t.start()
        return result

    def _get_challenge_seq(self):
        """
        生成挑战序列[{vi,ii}]
        vi 为随机数
        ii 为合法范围内的sub-block索引
        @return: [{vi,ii}]列表
        """
        vis = []
        iis = []
        for i in range(self.challenge_seq_len):
            vi = get_randomm_num(self.r_state, self.P)
            ii = random.randint(0, self.N - 1)
            vi = hex(vi)
            vis.append(vi)
            iis.append(ii)
        return vis, iis

    # 一维索引转换对应challenge block 的下标位置
    def _ii_to_challenge_block(self, ii):
        cj = ii % self.num_challenge_blocks
        return cj

    def _got_res_to_verification(self, u, q, iis, vis, A, K):
        """
        Verification
        校验存储服务器的结果是否正确
        @param u: 存储服务器计算结果
        @param q: 存储服务器计算结果
        @param iis: 挑战集合：challenge block 索引 ii
        @param vis: 挑战集合: 生成的随机数
        @param A: 文件认证符
        @param K: 文件认证符
        @return: 成功返回True
        """
        len = self.challenge_seq_len
        left = gmpy2.powmod(self.G, q, self.P)
        sum = gmpy2.mpz(0)
        for i in range(len):
            ii = iis[i]
            ii = self._ii_to_challenge_block(ii)
            vi = gmpy2.mpz(vis[i], 16)
            h = gmpy2.mpz(ii)
            t = gmpy2.mul(vi, h)
            sum = gmpy2.add(sum, t)
        right = gmpy2.powmod(K, sum, self.P)
        tmp = gmpy2.powmod(A, u, self.P)
        right = gmpy2.mul(right, tmp)
        right = gmpy2.t_mod(right, self.P)
        return gmpy2.cmp(left, right) == 0

    def _parse(self, msg):
        """
        解析文件元信息
        @param msg:
        @return:
        """
        msg_json = msg
        share_detail = ""
        shares = {}
        version = ''
        for k, v in msg_json.items():
            if k == "share_detail":
                share_detail = v
            elif k == "version":
                version = v
            else:
                d = v.get("server_address")
                shnum = k[-1]
                shares[shnum] = d[0][0]

        share_detail["storage_index"] = share_detail["storage_index"]
        share_detail["challenge_block_size"] = pdputil.CBLOCK_SIZE
        self.num_challenge_blocks = int(share_detail["block_size"] // pdputil.CBLOCK_SIZE)
        self.N = int(share_detail["share_size"] // pdputil.CBLOCK_SIZE)
        self.share_detail = share_detail
        self.shares = shares
        self.version = version
        self.challenge_seq_len = 10  # int(self.N//4)
        (A, K) = self._read_A_K(self.share_detail['storage_index'])
        self.A = A
        self.K = K

    # 读取文件的A和K
    def _read_A_K(self, si):
        """
        根据文件索引读取 A 和 K
        @param si: 文件索引
        @return:
        """

        si = base32.a2b(si.encode('utf-8'))
        hash = hashlib.sha256(si)
        result = self.eth.findFileAuthForIndex(hash.hexdigest())
        A = gmpy2.mpz(result[0], 16)
        K = gmpy2.mpz(result[1], 16)
        return A, K

        # path = "{}/{}".format(pdputil.BLOCKAUTH, si)
        # if not os.path.exists(path):
        #     return
        # with open(path, "r") as f:
        #     A = f.readline().strip()
        #     K = f.readline().strip()
        # A = gmpy2.mpz(A, 16)
        # K = gmpy2.mpz(K, 16)
        # return (A, K)

    def _send_challenge(self, vis, iis, shnum, ip, port):
        senddata = {
            "shnum": int(shnum),
            "version": self.version,
            "share_detail": self.share_detail,
            "iis": iis,
            "vis": vis
        }

        json_data = b2a(json.dumps(senddata).encode('utf-8'))
        datalen = len(json_data)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = (ip, 9999)
        try:
            sock.connect(server_address)
            datalen = struct.pack("Q", datalen)
            sock.send(datalen)
            sock.send(json_data)
            recvm = sock.recv(1024)
            recvm = json.loads(recvm.decode('utf-8'))  #
        finally:
            sock.close()
        u = recvm["u"]
        q = recvm["q"]
        u = gmpy2.mpz(u, 16)
        q = gmpy2.mpz(q, 16)
        return self._got_res_to_verification(u, q, iis, vis, self.A, self.K)
