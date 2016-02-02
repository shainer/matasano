#!/usr/bin/python
import base64
import encode_xor
import decode_xor

import sys
sys.path.insert(0, '/home/shainer/source/matasano/lib')
import utils

def _ByteToPaddedBin(byte):
	bin_str = '{0:b}'.format(byte)

	while len(bin_str) < 8:
		bin_str = '0' + bin_str

	return bin_str

def HammingDistance(s1, s2):
	assert len(s1) == len(s2)
	distance = 0

	for i in range(0, len(s1)):
		s1_byte = ord(s1[i])
		s2_byte = ord(s2[i])

		s1_bin = _ByteToPaddedBin(s1_byte)
		s2_bin = _ByteToPaddedBin(s2_byte)

		for j in range(0, len(s1_bin)):
			if s1_bin[j] != s2_bin[j]:
				distance += 1

	return distance

def HammingDistanceBin(b1, b2):
	assert len(b1) == len(b2)
	distance = 0

	for i in range(len(b1)):
		if b1[i] != b2[i]:
			distance += 1

	return distance

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
		
		ascii_res = utils.bin_to_ascii(decodings[0][1])

		# Unreadable ASCII.
		if not ascii_res[1]:
			return ''

		ascii_key += ascii_res[0]

	# Congratulations!
	return ascii_key

def sortKeysizes(bin_text, min_keysize, max_keysize):
	"""Sort all keysizes in the given range by their likelihood to be
	the real one for this binary text. Returns the sorted list."""
	keysizes_with_distance = {}

	for keysize in range(min_keysize, max_keysize+1):
		hamming_distance = 0

		# Number of blocks of KEYSIZE bytes in the text.
		num_blocks = int(len(bin_text) / (keysize * 8))

		# Takes the first pair of blocks of KEYSIZE bytes, then
		# the second pair, etc... (no overlapping). For each pair,
		# compare the Hamming distance between the two blocks and sum
		# it to the original one.
		for block_index in range(0, num_blocks):
			chunk1 = bin_text[block_index : block_index + keysize*8]
			chunk2 = bin_text[block_index + keysize*8 : block_index + keysize*16]

			block_index += (keysize * 16)
			hamming_distance += HammingDistanceBin(chunk1, chunk2)

		# The normalized distance is the Hamming distance divided by the
		# number of blocks and the key size.
		norm_distance = hamming_distance / (num_blocks * keysize)
		keysizes_with_distance[keysize] = norm_distance

	# Sort key sizes from lowest normalized distance to the highest.
	keysizes = sorted(
		keysizes_with_distance.keys(),
		key = lambda x : keysizes_with_distance[x])
	return keysizes

def breakXOR(text, min_keysize, max_keysize):
	bin_text = utils.base64_to_bin(text)

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
			utils.base64_to_ascii(encrypted_text), key))

