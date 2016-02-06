#!/usr/bin/python2

import aes_lib
import base64

from Crypto.Cipher import AES

def ByteXOR(s1, s2):
	"""Computes the XOR between two byte strings."""
	assert len(s1) == len(s2)
	res = ''

	for i in range(0, len(s1)):
		# Each byte is converted to a number, XORed, and then
		# converted back.
		n1 = ord(s1[i])
		n2 = ord(s2[i])
		res += chr(n1 ^ n2)

	return res

if __name__ == '__main__':
	ciphertext = ''

	with open('data/10.txt', 'r') as input_file:
		ciphertext = input_file.read()

	# IV here is just the byte 0 repeated 16 times.
	iv = '\x00' * AES.block_size
	key = b'YELLOW SUBMARINE'

	aes = aes_lib.AESCipher(key, mode=AES.MODE_ECB, iv=iv)

	# Decode the base64 ciphertext into a byte string.
	byte_cipher = base64.b64decode(ciphertext)

	# The loop simulates decryption through AES in CBC mode.
	# In such mode, the ciphertext is divided in blocks the size
	# of the key. Each block is decrypted, then the plaintext is XORed
	# with the previous ciphertext block. To initialize the algorithm,
	# an IV (initialization vector) is used.
	prev_ct = iv
	block_index = 0
	plaintext = ''

	while block_index < len(byte_cipher):
		block = byte_cipher[block_index : block_index + AES.block_size]

		prep_plaintext = aes.aes_decrypt(block)
		plaintext += ByteXOR(prev_ct, prep_plaintext)
		prev_ct = block

		block_index += AES.block_size

	print (plaintext)