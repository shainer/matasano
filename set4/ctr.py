#!/usr/bin/python3

import block_utils
from Crypto.Cipher import AES

class AESCtr(object):
	def __init__(self, key, nonce):
		self._nonce = nonce
		# In CTR mode, we use a regular ECB cipher to encrypt the
		# individual keystream blocks.
		self._cipher = AES.new(key=key, mode=AES.MODE_ECB)

	def OneBlockCrypt(self, block, counter):
		# The keystream generator is composed by 8 bytes of the nonce +
		# 8 bytes of counter, little-endian.
		keystreamGen = bytes([self._nonce]) * 8
		# This is a quick hack that only works if there are not enough
		# blocks of text to need 2 bytes to represent the counter. That
		# will mean less than 2^8 blocks, which is reasonable for now
		# so we can be lazy.
		keystreamGen += bytes([counter, 0, 0, 0, 0, 0, 0, 0])

		# Careful, we always encrypt the keystream even when decrypting.
		keystream = self._cipher.encrypt(keystreamGen)

		# The PT is simply the CT XORed with the keystream, and vice versa.
		# Since the PT only depends on the same block of CT plus a predictable
		# keystream, CTR is very suited for parallel decryption of many blocks.
		return block_utils.BlockXOR(block, keystream)

	def Crypt(self, text):
		"""The algorithm is the same for both encryption and decryption."""
		resultingText = b''
		keystream = b''

		# There is no padding in CTR mode, so both a plaintext and a ciphertext
		# can be of non-exact block size. We decrypt the last block by generating
		# the keystream and only using the bytes we need.
		numBlocks = block_utils.GetNumBlocks(text)
		counter = 0

		# +1 to get the final bytes that do not fit in a block.
		for blockIndex in range(0, numBlocks + 1):
			block = block_utils.GetSingleBlock(text, blockIndex)
			resultingText += self.OneBlockCrypt(block, counter)
			counter += 1

		return resultingText

def DoCTR(text, key, nonce):
	return AESCtr(key, nonce).Crypt(text)