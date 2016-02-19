#!/usr/bin/python3

import aes_lib
import base64

if __name__ == '__main__':
	ciphertext = ''

	with open('data/10.txt', 'r') as input_file:
		ciphertext = input_file.read()

	# This exercise also requires a specific IV!
	aes = aes_lib.AESCipher(b'YELLOW SUBMARINE', iv=b'\x00' * 16)

	# Decode the base64 ciphertext into a byte string.
	byte_cipher = base64.b64decode(ciphertext)
	print (aes.SimulateCBCDecryption(byte_cipher).decode('ascii'))
