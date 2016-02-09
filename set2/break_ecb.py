#!/usr/bin/python

import aes_lib
import base64
import collections

from Crypto.Cipher import AES
from Crypto import Random

def CountRepeatedBlocks(byte_string, chunk_size):
	"""Counts how many 16-bytes chunks in the string are
	repeated more than once. The input is a byte string."""
	chunk_start = 0

	# New keys get a default value of 0. The dictionary will
	# count the number of occurrences of each 16-bytes chunk in
	# the string.
	chunkCounter = collections.defaultdict(int)

	while chunk_start < len(byte_string):
		chunk = byte_string[chunk_start : chunk_start + chunk_size]
		chunkCounter[chunk] += 1
		chunk_start += chunk_size

	# This generator adds 1 for each value in the dictionary that
	# is greater than 1.
	return sum(1 for c in chunkCounter if chunkCounter[c] > 1)


def GetBlockSize(encrypter):
	pad = ''
	initial_len = len(encrypter.Encrypt(pad))
	l = initial_len

	# Find 'l' such that the complete plaintext used to produce it
	# has no padding at the end. This means the ciphertext length
	# actually increased when we added more plaintext, signaling
	# that we added a new ciphertext block.
	while l == initial_len:
		pad += 'A'
		l = len(encrypter.Encrypt(pad))

	# Find 'l2' such as it is the next ciphertext length with the
	# same property as 'l'. We added yet another block to the
	# ciphertext.
	l2 = l
	while l2 == l:
		pad += 'A'
		l2 = len(encrypter.Encrypt(pad))

	# The distance between them is the size of one block.
	return (l2 - l)

def DetectEncryptionMode(ciphertext, block_size):
	"""We can only recognize ECB if there is at least one repeated block
	in the ciphertext. But this won't always work, as different input
	blocks will produce different output blocks with ECB too."""
	repetitions = CountRepeatedBlocks(ciphertext, block_size)
	return AES.MODE_ECB if repetitions > 0 else AES.MODE_CBC

def ModeToString(mode):
	"""Convenience method for printing AES modes."""
	if mode == 1:
		return 'ECB'
	elif mode == 2:
		return 'CBC'

def GetNumSecretBlocks(enc, block_size):
	# Add no plaintext of our own to find out how many are
	# appended by the encrypter.
	c = enc.Encrypt('')
	return len(c) / block_size

def BreakECB(enc, block_size):
	"""Breaks this specific ECB oracle given the block size we computed before."""
	broken_text = ''
	num_secret_blocks = GetNumSecretBlocks(enc, block_size)

	# List of ASCII readable bytes as decimal integers.
	readable_bytes = [10] + range(32, 127)

	# We can discover one byte of the "secret string" with this method:
	# 1. Encrypt a plaintext formed by as many A as the block size minus 1.
	# 2. The last byte of the block will be filled with the first byte of the text to break.
	# 3. We generate all possibilities for the complete block by appending each possible
	# readable byte (n below).
	# 4. By comparing the encrypted blocks, we can find out the correct plaintext byte.
	#
	# Let's say the first discovered byte is X. Now we encrypt a plaintext
	# formed by as many A as the block size minus 2. The encrypter will add X and another byte
	# to complete the block, so we can repeat the procedure and find the second byte.
	#
	# When the first block has been completely decrypted, we just repeat the same procedure,
	# but we compare bytes from the 2nd block, and then the 3rd... since we already know
	# the whole plaintext that comes before that.
	for k in range(0, num_secret_blocks):
		for b in range(block_size - 1, -1, -1):
			oneshort = enc.Encrypt('A' * b)
			# Get only the block we are currently decrypting.
			oneshort = oneshort[block_size * k : block_size * (k+1)]

			for n in readable_bytes:
				# The generated plaintext here contains the same padding as the
				# original one, plus the secret key plaintext we discovered (if any),
				# and the current guess for the next byte.
				pt = ('A' * b) + broken_text + chr(n)
				calculated = enc.Encrypt(pt)
				# Get the block we are currently decrypting.
				calculated = calculated[block_size * k : block_size * (k+1)]

				if calculated == oneshort:
					broken_text += chr(n)
					break

	# Chop to known size otherwise we also returned the random padding at the end.
	return broken_text[:num_secret_blocks * block_size]


if __name__ == '__main__':
	enc = aes_lib.RandomizedCipher()

	block_size = GetBlockSize(enc)
	print "[**] Detected block size is " + str(block_size)

	ciphertext = enc.Encrypt(b'A' * (block_size * 2))
	mode = DetectEncryptionMode(ciphertext, block_size)

	if mode != AES.MODE_ECB:
		print "[!!] Wrong encryption mode detected: " + str(mode)
		exit(0)

	print "[**] Detected mode is: " + ModeToString(mode)

	plaintext = BreakECB(enc, block_size)
	print "[**] Uncovered plaintext: "
	print plaintext
