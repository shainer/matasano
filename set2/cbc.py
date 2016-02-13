#!/usr/bin/python

import aes_lib
import base64

if __name__ == '__main__':
	ciphertext = ''

	with open('data/10.txt', 'r') as input_file:
		ciphertext = input_file.read()

	aes = aes_lib.AESCipher(b'YELLOW SUBMARINE')

	# Decode the base64 ciphertext into a byte string.
	byte_cipher = base64.b64decode(ciphertext)
	print (aes.SimulateCBCDecryption(byte_cipher))
