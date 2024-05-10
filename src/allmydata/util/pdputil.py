import binascii
import gmpy2

from allmydata.util import base32

BLOCKAUTH="/Users/mrl/blockAuth"
CBLOCK_SIZE=16 # B
CHECK_CODE_SIZE=64 # B

def convert_bytes_to_mpz(bytes):
    b = binascii.hexlify(bytes)
    mpz_representation = gmpy2.mpz(b,16)
    return mpz_representation


def convert_mpz_to_bytes(r):
    r_hex = hex(r)[2:]
    while len(r_hex) < 128:
        r_hex = '0' + r_hex
    bytes = binascii.unhexlify(r_hex)
    return bytes



def get_randomb_pnum(self, r_state, cnt):
    random_num = gmpy2.mpz_urandomb(r_state, cnt)
    random_pnum = gmpy2.next_prime(random_num)
    return random_pnum