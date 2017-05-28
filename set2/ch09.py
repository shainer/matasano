#!/usr/bin/python3

# Set 2, challenge 9: implement PKCS#7 padding.

from pkcs7 import Pkcs7

if __name__ == '__main__':
	print(Pkcs7(b'YELLOW SUBMARINE', 20))

