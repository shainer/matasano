#!/usr/bin/python3

import base64
from Crypto.Cipher import AES
from Crypto import Random
import struct

class AESCipher():
	def __init__(self, key, mode=AES.MODE_ECB):
		"""Initialize a AES cipher with the given mode, and key (as a byte string)"""
		self._iv = Random.new().read(AES.block_size)
		self._cipher = AES.new(key, mode=mode, IV=self._iv)

	def aes_decrypt(self, message):
		"""Decrypt a message under the cipher. The message should be a byte string."""
		return self._cipher.decrypt(message)

if __name__ == '__main__':
	ciphertext = ''

	with open('data/7.txt', 'r') as input_file:
		ciphertext = input_file.read()

	aes = AESCipher(b'YELLOW SUBMARINE')
	print(aes.aes_decrypt(base64.b64decode(ciphertext)).decode('ascii'))
