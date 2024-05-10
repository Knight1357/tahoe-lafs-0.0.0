import hashlib

from allmydata.immutable.ethfactory import EthWorker
from allmydata.util.assertutil import precondition
from allmydata.storage.common import si_b2a
from allmydata.util import pdputil
import random
from allmydata.util import log

import gmpy2

from allmydata.util.base32 import b2a


# 生成随机种子
def get_rand_state():
    r_state = gmpy2.random_state(random.randint(1, 100))
    return r_state


# 返回cnt位的随机数
# 大小为 0~2^{n-1}
def get_randomb_num(r_state, cnt):
    # gmpy2.mpz_urandomb(random_state, bit_count, /)→ mpz
    # Return uniformly distributed random integer between 0 and 2**bit_count-1.
    random_num = gmpy2.mpz_urandomb(r_state, cnt)
    return random_num


# 返回0-(n-1)范围随机数
def get_randomm_num(r_state, cnt):
    # gmpy2.mpz_random(random_state, int, /)→ mpz
    # Return uniformly distributed random integer between 0 and n-1.
    random_num = gmpy2.mpz_random(r_state, cnt)
    return random_num


def response_challenge_seq(iis, vis, blocks, challenge_block_checkcodes):
    """
    Resp
    存储端接受挑战序列进行校验
    @param iis: 挑战集合：challenge block 索引列表
    @param vis: 挑战集合：随机数
    @param blocks: 对应索引的challenge block 列表
    @param challenge_block_checkcodes: 对应challenge block的文件标签
    @return: 计算结果
    """
    seq_len = len(iis)
    # vi * challenge block content
    u = gmpy2.mpz()
    for i in range(seq_len):
        vi = vis[i]
        challenge_block_mpz = blocks[i]
        t = gmpy2.mul(vi, challenge_block_mpz)
        u = gmpy2.add(u, t)
    q = gmpy2.mpz()
    # vi * challenge block checkcode
    for i in range(seq_len):
        vi = vis[i]
        checkcode = challenge_block_checkcodes[i]
        t = gmpy2.mul(vi, checkcode)
        q = gmpy2.add(q, t)
    return u, q


class Pdp(object):

    def __init__(self, log_parent=None):
        self._eth = EthWorker()
        self.a = None
        self.kprf = None
        self.A = None
        self.K = None
        self.g = gmpy2.mpz(
            "8744930370936677675691572579627854348401591927865428209403276589124198778726853734619578370823207519321616080054674049209442452175828495599202899292300093"
        )
        self.p = gmpy2.mpz(
            "2630373295987918856248717725661016679397663965838488940293176904082486592825725810999021962983421413017941758493846955484028971753362061491943145531337277"
        )
        self.cblock_size = 16
        self.ccode_size = 64
        self.num_challenge_blocks = 0
        self.challenge_seq_len = 1
        precondition(log_parent is None or isinstance(log_parent, int), log_parent)
        self._log_number = log.msg(
            "creating pdp %s" % self, facility="schain.pdp", parent=log_parent
        )

    def save_A_K(self, storage_index):
        fileIndex = hashlib.sha256(storage_index)
        self._eth.storeFileAuth(fileIndex.hexdigest(), hex(self.A), hex(self.K))
        # sia = si_b2a(storage_index).decode("ascii")
        # path = "{}/{}".format(pdputil.BLOCKAUTH, sia)
        # with open(path, "w") as f:
        #     f.write(hex(self.A) + "\n")
        #     f.write(hex(self.K) + "\n")

    def get_primenum(self, r_state):
        p = pdputil.get_randomb_pnum(r_state, 512)
        return p

    def init(self):
        self.kprf = self.get_kprf()
        self.K = self.get_public_key(self.kprf)
        self.a = self.get_random_a()
        self.A = self.get_A(self.a)

    # 随机生成kprf
    def get_kprf(self):
        """
        随机生成kprf
        @return: 1023位的随机数
        """
        r_state = get_rand_state()
        kprf = get_randomb_num(r_state, 1023)
        return kprf

    def get_public_key(self, kprf):
        """
        通过kprf得到K
        @param kprf:
        @return: K
        """
        K = gmpy2.powmod(self.g, kprf, self.p)
        return K

    # 计算随机数a
    def get_random_a(self):
        r_state = get_rand_state()
        a = get_randomb_num(r_state, 1023)
        return a

    # 计算A
    def get_A(self, a):
        A = gmpy2.powmod(self.g, a, self.p)
        return A

    def log(self, *args, **kwargs):
        if "parent" not in kwargs:
            kwargs["parent"] = self._log_number
        if "facility" not in kwargs:
            kwargs["facility"] = "schain.pdp"
        return log.msg(*args, **kwargs)

    def keyGen(self, block):
        """
        按照challenge block大小拆分block计算对应的checkcode
        checkcode:64B
        challenge block:16B
        @param block:
        @return: ccodes:当前block的checkcode 列表
        """
        ccodes = {}
        cblock_cnt = int(len(block) // pdputil.CBLOCK_SIZE)
        for i in range(cblock_cnt):
            offset = i * pdputil.CBLOCK_SIZE
            if(offset + pdputil.CBLOCK_SIZE > len(block)):
                break
            cblock = block[offset: offset + pdputil.CBLOCK_SIZE]
            # print("cblock offset=[{}:{}]".format(offset, offset + pdputil.CBLOCK_SIZE))
            cblock_mpz = pdputil.convert_bytes_to_mpz(cblock)
            h = gmpy2.mpz(i)
            t1 = gmpy2.mul(h, self.kprf)  # h(i) * kprf
            t2 = gmpy2.mul(self.a, cblock_mpz)
            t = gmpy2.add(t1, t2)
            t = gmpy2.t_mod(t, gmpy2.sub(self.p, 1))
            t = pdputil.convert_mpz_to_bytes(t)
            ccodes[i] = t
        return ccodes

    def ii_to_block(self, ii, num_challenge_block):
        bi = ii / num_challenge_block
        cj = ii % num_challenge_block
        offset = (cj - 1) * pdputil.CBLOCK_SIZE
        return (bi, offset)
