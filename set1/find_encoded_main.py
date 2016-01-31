#!/usr/bin/python

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

		# We need at least one candidate. For now we assume there is
		# exactly one.
		if candidates:
			print ('String ' + string + ' decoded to ' + candidates[0][0])

