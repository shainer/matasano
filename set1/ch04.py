#!/usr/bin/python3

# Set 1, challenge 4: detect single-character XOR.

import decode_xor

if __name__ == '__main__':
	strings = []

	with open('data/encrypted.txt', 'r') as data_file:
		strings = data_file.readlines()

	decoder = decode_xor.XORDecoder(8)

	for string in strings:
		# Remove trailing newlines.
		string = string.strip()

		candidates = decoder.DecodeHex(string)

		if candidates:
			print('String %s decoded to \"%s\"'
					% (string, candidates[0][0]))
			break

