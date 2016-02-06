#!/usr/bin/python2

from Crypto.Cipher import AES
from Crypto import Random

import aes_lib
import collections
import random

def GenerateRandomBytes(size):
	"""Random byte string of given size."""
	return Random.new().read(size)

def RandomEncrypt(plaintext):
	"""Returns a tuple with the encrypted text and the mode used."""
	# Random key.
	key = GenerateRandomBytes(AES.block_size)

	# Random padding both before and after the plaintext. The
	# size of the second padding cannot be random since the result
	# needs to have a number of bytes multiple of 16.
	paddingSize = random.randint(5, 10)
	prepend = GenerateRandomBytes(paddingSize)
	append = GenerateRandomBytes(AES.block_size - paddingSize)

	# Pick encryption mode at random.
	mode = None
	if random.randint(0, 1) == 0:
		mode = AES.MODE_ECB
	else:
		mode = AES.MODE_CBC

	# Perform the encryption.
	aes = aes_lib.AESCipher(key, mode=mode)
	text = prepend + plaintext + append
	return (aes.aes_encrypt(text), mode)

def CountRepeatedBlocks(byte_string):
	"""Counts how many 16-bytes chunks in the string are
	repeated more than once. The input is a byte string."""
	chunk_start = 0
	CHUNK_SIZE = 16

	# New keys get a default value of 0. The dictionary will
	# count the number of occurrences of each 16-bytes chunk in
	# the string.
	chunkCounter = collections.defaultdict(int)

	while chunk_start < len(byte_string):
		chunk = byte_string[chunk_start : chunk_start + CHUNK_SIZE]
		chunkCounter[chunk] += 1
		chunk_start += CHUNK_SIZE

	# This generator adds 1 for each value in the dictionary that
	# is greater than 1.
	return sum(1 for c in chunkCounter if chunkCounter[c] > 1)

def DetectEncryptionMode(ciphertext):
	"""We can only recognize ECB if there is at least one repeated block
	in the ciphertext. But this won't always work, as different input
	blocks will produce different output blocks with ECB too."""
	repetitions = CountRepeatedBlocks(ciphertext)
	return AES.MODE_ECB if repetitions > 0 else AES.MODE_CBC

def ModeToString(mode):
	"""Convenience method for printing AES modes."""
	if mode == 1:
		return 'ECB'
	elif mode == 2:
		return 'CBC'

if __name__ == '__main__':
	plaintext = b'B' * 1024

	ciphertext, realMode = RandomEncrypt(plaintext)
	mode = DetectEncryptionMode(ciphertext)

	print ('[**] Mode ' + ModeToString(mode) + ' detected.')
	print ('[**] Real mode was ' + ModeToString(realMode))
