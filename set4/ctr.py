#!/usr/bin/python3

from Crypto.Cipher import AES

def BlockXOR(b1, b2):
	"""XOR of two blocks of bytes. b2 is allowed to be longer
	than b1, the extra bytes will simply be ignored."""
	res = b''

	for bIndex in range(0, len(b1)):
		res += bytes([b1[bIndex] ^ b2[bIndex]])

	return res

def DoCTR(text, key, nonce):
	"""The algorithm is the same for both encryption and decryption."""
	# Uses ECB inside for a single block.
	cipher = AES.new(key=key, mode=AES.MODE_ECB)
	resultingText = b''

	keystream = b''
	# There is no padding in CTR mode, so both a plaintext and a ciphertext
	# can be of non-exact block size. We decrypt the last block by generating
	# the keystream and only using the bytes we need.
	numBlocks = int(len(text) / AES.block_size)
	counter = 0

	# +1 to get the final bytes that do not fit in a block.
	for blockIndex in range(0, numBlocks + 1):
		# If at the end, simply get all the remaining bytes; there
		# will be exactly AES.block_size or less of them. Otherwise,
		# get a block.
		if blockIndex == numBlocks:
			block = text[blockIndex * AES.block_size :]
		else:
			block = text[blockIndex * AES.block_size : (blockIndex + 1) * AES.block_size]

		# The keystream generator is composed by 8 bytes of the nonce +
		# 8 bytes of counter, little-endian.
		keystreamGen = bytes([nonce]) * 8
		# This is a quick hack that only works if there are not enough
		# blocks of text to need the second digit of the counter too.
		# Since that is a lot of blocks we can be a bit lazy.
		keystreamGen += bytes([counter, 0, 0, 0, 0, 0, 0, 0])

		# Careful, we always encrypt the keystream even when decrypting.
		keystream = cipher.encrypt(keystreamGen)

		# The PT is simply the CT XORed with the keystream, and vice versa.
		# Since the PT only depends on the same block of CT plus a predictable
		# keystream, CTR is very suited for parallel decryption of many blocks.
		resultingText += BlockXOR(block, keystream)
		counter += 1

	return resultingText
