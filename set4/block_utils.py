#!/usr/bin/python3

import math
from Crypto.Cipher import AES

def BlockXOR(b1, b2):
	"""XOR of two blocks of bytes. b2 is allowed to be longer
	   than b1, the extra bytes will simply be ignored."""
	res = b''

	for bIndex in range(0, len(b1)):
		res += bytes([b1[bIndex] ^ b2[bIndex]])

	return res

def GetNumBlocks(text, blockSize=AES.block_size):
	return int(math.ceil(len(text) / blockSize))

def GetSingleBlock(text, index, blockSize=AES.block_size):
	# If at the end, simply get all the remaining bytes; there
	# will be exactly AES.block_size or less of them. Otherwise,
	# get a block.
	if index == GetNumBlocks(text, blockSize):
		block = text[index * blockSize :]
	else:
		block = text[index * blockSize : (index + 1) * blockSize]

	return block