#!/usr/bin/python3

# Set 2, challenge 14: byte-at-a-time ECB decryption (harder).

import aes_lib
import ch12
import collections
from Crypto.Cipher import AES

class NoValidPlaintextError(Exception):
	pass

# This is not affected by the presence of the random prefix, so
# this is equivalent to the version in challenge 12, save for the
# encryption method we call.
def GetBlockSize(encrypter):
	pad = b''
	initial_len = len(encrypter.EncryptWithRandomPad(pad))
	l = initial_len

	# Find 'l' such that the complete plaintext used to produce it
	# has no padding at the end. This means the ciphertext length
	# actually increased when we added more plaintext, signaling
	# that we added a new ciphertext block.
	while l == initial_len:
		pad += b'A'
		l = len(encrypter.EncryptWithRandomPad(pad))

	# Find 'l2' such as it is the next ciphertext length with the
	# same property as 'l'. We added yet another block to the
	# ciphertext.
	l2 = l
	while l2 == l:
		pad += b'A'
		l2 = len(encrypter.EncryptWithRandomPad(pad))

	# The distance between them is the size of one block.
	return (l2 - l)

def GetRandomPrefixLen(enc, block_size):
	"""Discovers the length of the random prefix prepended to every
	plaintext, given the block size.

	CAVEAT EMPTOR! If the prefix length is bigger than the block size,
	this will noy work properly; if block size is 16 and prefix length
	is 19, we will return 3. I am not sure how to eliminate the
	ambiguity.
	"""
	textSize = block_size * 2
	mode = None

	# When we detected the encryption mode, we had to use 3 blocks
	# of plaintext to be sure of getting 2 identical blocks of
	# ciphertext, due to the random length of the prefix.
	#
	# Here we start from 2 blocks of identical plaintext, and add
	# one byte until we get 2 blocks of identical ciphertext (which
	# is equivalent to our detection function successfully recognizing
	# ECB mode). At this point, the block size - the number of bytes
	# we had to add before succeeding is the length of the prefix.
	while mode != AES.MODE_ECB:
		ciphertext = enc.EncryptWithRandomPad(b'A' * textSize)
		mode = ch12.DetectEncryptionMode(ciphertext, block_size)
		textSize += 1

	return (block_size - (textSize - (block_size * 2)) + 1)


def BreakECB(enc, block_size, prefix_len):
	"""Breaks this specific ECB oracle given the block size and the length
	of the prefix computed before."""
	broken_text = b''
	num_secret_blocks = ch12.GetNumSecretBlocks(enc, block_size)

	# Once we know the prefix length, we add more padding so that our
	# prefix now occupies whole blocks. At this point the algorithm is
	# the same as before, just remember to ignore the padded blocks
	# (num_prefix_blocks).
	prepad = b''
	while (len(prepad) + prefix_len) % block_size != 0:
		prepad += b'C'
	num_prefix_blocks = int((len(prepad) + prefix_len) / block_size)

	# List of ASCII readable bytes as decimal integers.
	readable_bytes = [10] + list(range(32, 127))

	# See ch12.py for the explanation of this algorithm; the only difference
	# is that we ignore the first block(s) to avoid the random prefix.
	for k in range(num_prefix_blocks, num_secret_blocks):
		for b in range(block_size - 1, -1, -1):
			oneshort = enc.EncryptWithRandomPad(prepad + (b'A' * b))
			# Get only the block we are currently decrypting.
			oneshort = oneshort[block_size * k : block_size * (k+1)]

			for n in readable_bytes:
				# The generated plaintext here contains the same padding as the
				# original one, plus the secret key plaintext we discovered (if any),
				# and the current guess for the next byte.
				pt = prepad + (b'A' * b) + broken_text + bytes([n])
				calculated = enc.EncryptWithRandomPad(pt)
				# Get the block we are currently decrypting.
				calculated = calculated[block_size * k : block_size * (k+1)]

				if calculated == oneshort:
					broken_text += bytes([n])
					break
			else:
				raise NoValidPlaintextError('No possible readable byte detected')

	# Chop to known size otherwise we also return the random padding at the end.
	return broken_text[:num_secret_blocks * block_size]

if __name__ == '__main__':
	enc = aes_lib.RandomizedCipher()

	block_size = GetBlockSize(enc)
	print('[**] Detected block size is ' + str(block_size))

	# 2 blocks with the same plaintext are not enough to guarantee
	# two identical ciphertext blocks here; this is due to the presence
	# of the random prefix which will cause the first A to be positioned
	# in the middle of a block rather than at the beginning. No fear,
	# we'll just add a new one.
	ciphertext = enc.EncryptWithRandomPad(b'A' * (block_size * 3))
	mode = ch12.DetectEncryptionMode(ciphertext, block_size)

	if mode != AES.MODE_ECB:
		print("[!!] Wrong encryption mode detected: " + str(mode))
		exit(0)

	print("[**] Detected mode is: " + ch12.ModeToString(mode))

	prefix_len = GetRandomPrefixLen(enc, block_size)
	print ('[**] Uncovered prefix length is ' + str(prefix_len))

	# Given the issue with GetRandomPrefixLen, we don't know for instance
	# whether our prefix length is 3 or 19, so in case we are unable to
	# find a valid plaintext, we just try the next possible prefix length.
	while True:
		try:
			plaintext = BreakECB(enc, block_size, prefix_len)
			# Found it!
			print("[**] Uncovered plaintext: " + plaintext.decode('ascii'))
			break
		except NoValidPlaintextError:
			prefix_len += block_size
			print("Trying prefix_len = " + str(prefix_len))
