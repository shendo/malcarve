# Malcarve - Obfuscated payload extractor for malware samples
# Copyright (C) 2016 Steve Henderson
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import timeit

def test_xor_perf():
    """
    This is NOT intended as a benchmark against pycrypto library but a check to ensure that
    the malcarve c implementation performance is sane and not doing anything stupid.
    """
    print("1 byte XOR 2MB buffer 100 iterations...")
    print("pycrypto lib:", timeit.timeit("c.encrypt(buf)", setup="from Crypto.Cipher import XOR ; import random; c=XOR.new(b'a'); buf = bytes([random.randint(0, 255) for _ in range(2048000)])", number=100))
    print("malcarve lib:", timeit.timeit("xor.xor(buf, b'a', 0, 0, False)", setup="import random; from malcarve.schemes import xor; buf = bytes([random.randint(0, 255) for _ in range(2048000)])", number=100))
    print("malcarve lib (null preserve):", timeit.timeit("xor.xor(buf, b'a', 0, 0, True)", setup="import random; from malcarve.schemes import xor; buf = bytes([random.randint(0, 255) for _ in range(2048000)])", number=100))
    print("malcarve lib (countup):", timeit.timeit("xor.xor(buf, b'a', 0, 1, False)", setup="import random; from malcarve.schemes import xor; buf = bytes([random.randint(0, 255) for _ in range(2048000)])", number=100))
    print("")
    print("8 byte XOR 2MB buffer 100 iterations...")
    print("pycrypto lib:", timeit.timeit("c.encrypt(buf)", setup="from Crypto.Cipher import XOR ; import random; c=XOR.new(b'abcdefgh'); buf = bytes([random.randint(0, 255) for _ in range(2048000)])", number=100))
    print("malcarve lib:", timeit.timeit("xor.xor(buf, 'abcdefgh', 0, 0, False)", setup="import random; from malcarve.schemes import xor; buf = bytes([random.randint(0, 255) for _ in range(2048000)])", number=100))
    print("malcarve lib (null preserve):", timeit.timeit("xor.xor(buf, b'abcdefgh', 0, 0, True)", setup="import random; from malcarve.schemes import xor; buf = bytes([random.randint(0, 255) for _ in range(2048000)])", number=100))
    print("malcarve lib (countup):", timeit.timeit("xor.xor(buf, b'abcdefgh', 0, 1, False)", setup="import random; from malcarve.schemes import xor; buf = bytes([random.randint(0, 255) for _ in range(2048000)])", number=100))
    print("malcarve lib (rolling):", timeit.timeit("xor.xor(buf, b'abcdefgh', 0, 0, False, True)", setup="import random; from malcarve.schemes import xor; buf = bytes([random.randint(0, 255) for _ in range(2048000)])", number=100))

if __name__ == '__main__':
    test_xor_perf()
