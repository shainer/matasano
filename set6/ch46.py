#!/usr/bin/python3

import base64
import math
import utils
import rsa

# Set 6, challenge 46: RSA parity oracle.

class ParityOracle(object):
	def __init__(self, key):
		self._key = key

	def IsEven(self, ciphernum):
		plainnum = rsa.Decrypt(self._key, ciphernum)
		return (plainnum % 2 == 0)

def numtobytes(k):
    return k.to_bytes((k.bit_length() + 7) // 8, byteorder='big')

if __name__ == '__main__':
	# Generate pair, "give" the private key to the oracle.
	publicKey, privateKey = rsa.GenerateRSAPair(1024)
	oracle = ParityOracle(privateKey)

	# Get the secret text, transform it into a number (the byte order
	# is not important as long as you always use the same), and encrypt
	# it with the public key.
	secretText = base64.b64decode('VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==')
	secret = int.from_bytes(secretText, byteorder='big')
	ciphernum = rsa.Encrypt(publicKey, secret)

	lowerBound = 0
	upperBound = privateKey[1]  # i.e. n
	e, n = publicKey

	m = utils.modexp(2, e, n)
	c = ciphernum

	while lowerBound != upperBound:
		c = (c * m) % n

		if oracle.IsEven(c):
			upperBound -= (upperBound - lowerBound) // 2
		else:
			lowerBound += (upperBound - lowerBound) // 2

		if upperBound - lowerBound == 1:
			break

		if upperBound < lowerBound:
			raise Exception('nope')

		# TODO: find out why there are rounding errors at the last 1-2 bytes
		# which means we don't always get the exact result at the end.
		print(numtobytes(upperBound))
