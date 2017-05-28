#!/usr/bin/python

# Set 1, challenge 8: detect AES in ECB mode.

import collections

def CountRepeatedBlocks(hex_string):
	"""Counts how many 16-bytes chunks in the string are
	repeated more than once. The input is an hexadecimal string."""
	chunk_start = 0
	CHUNK_SIZE = 32

	# New keys get a default value of 0. The dictionary will
	# count the number of occurrences of each 16-bytes chunk in
	# the string.
	chunkCounter = collections.defaultdict(int)

	while chunk_start < len(hex_string):
		chunk = hex_string[chunk_start : chunk_start + CHUNK_SIZE]
		chunkCounter[chunk] += 1
		chunk_start += CHUNK_SIZE

	# This generator adds 1 for each value in the dictionary that
	# is greater than 1.
	return sum(1 for c in chunkCounter if chunkCounter[c] > 1)


if __name__ == '__main__':
	ecb_candidates = []

	with open('data/8.txt', 'r') as f:
		ecb_candidates = f.readlines()

	repetitions = {}

	for c in ecb_candidates:
		candidate = c.strip()  # eliminates trailing newline
		repeatedCount = CountRepeatedBlocks(candidate)

		if repeatedCount > 0:
			repetitions[candidate] = repeatedCount

	# The block we find here is not encrypted with the 'YELLOW SUBMARINE'
	# key. I tried just in case there was a surprise :-)
	for c in repetitions:
		print (c + ' has ' + str(repetitions[c]) +
			   ' block(s) repeated more than once.')