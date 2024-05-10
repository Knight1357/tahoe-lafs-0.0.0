# -* e
import gmpy2
import time

from allmydata.util import base32

a = gmpy2.mpz('12312321312')
b = gmpy2.mpz('827398223232273892')
aByte = gmpy2.to_binary(a)
bByte = gmpy2.to_binary(b)
print(aByte)
print(bByte)
aByte = base32.b2a(gmpy2.to_binary(a))
print(aByte)




