
import os
import unittest
from allmydata.util import pdputil


class TestGmpy2Convert(unittest.TestCase):
    def test_64byte_mpz(self):
        random_byte = os.urandom(64)
        mpz_number = pdputil.convert_bytes_to_mpz(random_byte)
        convert_byte = pdputil.convert_mpz_to_bytes(mpz_number)
        convert_number = pdputil.convert_bytes_to_mpz(convert_byte)
        self.assertEqual(convert_number,mpz_number)
    def test_byte_mpz(self):
        bytes = b'\xb8P4_\xceY\x1a8\xab\x04dDJ\xf8\xc8\xb6'
        number = pdputil.convert_bytes_to_mpz(bytes)
        convert_byte = pdputil.convert_mpz_to_bytes(number)
        convert_number = pdputil.convert_bytes_to_mpz(convert_byte)
        self.assertEqual(number,convert_number)

    def test_conver(self):
        input=[]
        for i in range(10):
            random_byte = os.urandom(64)

            list.append(random_byte)


