#!/usr/bin/python3

# Set 1, challenge 6: break repeating-key XOR

import base64
import encode_xor
import decode_xor

from utils import encoding_utils as enclib

def findKey(bin_text, keysize):
	"""Try to find the encoding key of given size for bin_text.

	Returns the key in ASCII if found, or empty key otherwise.
	"""
	decoder = decode_xor.XORDecoder(8)

	blocks = []
	bin_key = ''
	ascii_key = ''

	# We crack the key byte by byte. First, we divide the text in blocks
	# of KEYSIZE length each; then we build the ith item of the blocks
	# list to contain the ith byte from each of the KEYSIZE blocks.
	# This means that for each element of blocks, the key is one byte of 
	# the final key we want to find. We crack element by element until
	# we can build the complete key.
	block_pos = 0
	while block_pos < keysize:
		blocks.append('')
		cur_pos = (block_pos * 8)

		while cur_pos < len(bin_text):
			piece = bin_text[cur_pos:cur_pos+8]
			blocks[block_pos] += piece

			# Move to the next block.
			cur_pos += (keysize * 8)

		block_pos += 1

	for block in blocks:
		# This decodes single-byte XOR for a binary string.
		decodings = decoder.DecodeBin(block, True)

		# We should be able to build the whole key. If one piece
		# is missing, just return.
		if not decodings:
			return ''
		
		ascii_res = enclib.BinToAscii(decodings[0][1])

		# Unreadable ASCII.
		if not ascii_res[1]:
			return ''

		ascii_key += ascii_res[0]

	# Congratulations!
	return ascii_key

def NormalizedHammingDistance(bin_text, keysize):
	"""Computes the normalized average Hamming distance between
	consecutive pairs of bin_text blocks of KEYSIZE bytes.

	The lowest this result is, the more are consecutive blocks of
	KEYSIZE bytes likely to be similar to each other; this means 
	that they were likely encoded with the same set of characters,
	and therefore the key could be of KEYSIZE length (in bytes).
	"""
	hamming_distance = 0

	# Number of blocks of KEYSIZE bytes in the text.
	num_blocks = int(len(bin_text) / (keysize * 8))
	# Keeps track of the first bit of the pair of chunks we
	# are considering
	start_block_index = 0

	# Takes the first pair of blocks of KEYSIZE bytes, then
	# the second pair, etc... (no overlapping). For each pair,
	# compare the Hamming distance between the two blocks and sum
	# it to our accumulator.

	# For some keysizes there are leftover data at the end that
	# cannot be divided in two chunks of the required size; in that
	# case we ignore them and stop before.
	end_block = len(bin_text) - (keysize * 16)
	while start_block_index <= end_block:
		# Each binary chunk is therefore of size keysize*8.
		chunk1 = bin_text[start_block_index : start_block_index + keysize*8]
		chunk2 = bin_text[start_block_index + keysize*8 : start_block_index + keysize*16]

		hamming_distance += enclib.HammingDistance(chunk1, chunk2)
		start_block_index += (keysize * 16)

	# The normalized distance is the Hamming distance divided by the
	# number of blocks and the key size.
	return (hamming_distance / (num_blocks * keysize))


def sortKeysizes(bin_text, min_keysize, max_keysize):
	"""Sort all keysizes in the given range by their likelihood to be
	the real one for this binary text. Returns the sorted list."""
	keysizes_with_distance = {}

	for keysize in range(min_keysize, max_keysize+1):
		keysizes_with_distance[keysize] = (
			NormalizedHammingDistance(bin_text, keysize))

	# Sort key sizes from lowest normal distance to the highest.
	return sorted(
		keysizes_with_distance.keys(),
		key = lambda x : keysizes_with_distance[x])

def breakXOR(text, min_keysize, max_keysize):
	bin_text = enclib.Base64ToBin(text)

	keysizes = sortKeysizes(bin_text, min_keysize, max_keysize)
	print('[**] Keysizes: ', str(keysizes))

	for keysize in keysizes[:5]:
		key = findKey(bin_text, keysize)

		if key:
			return key

	return ''

if __name__ == "__main__":
	encrypted_text = ''
	with open('data/6.txt', 'r') as f:
		encrypted_text = f.read()

	key = breakXOR(encrypted_text, 2, 40)
	if key:
		print('[**] Key found: ' + key)
		print('*** DECRYPTED MESSAGE ***')

		encoder = encode_xor.XOREncoder()
		print(encoder.EncodeAsAscii(
			enclib.Base64ToAscii(encrypted_text), key))
