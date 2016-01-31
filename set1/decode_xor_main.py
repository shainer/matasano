#!/usr/bin/python

import decode_xor

if __name__ == "__main__":
	s = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
	decoder = decode_xor.XORDecoder(8)

	candidates = decoder.Decode(s)
	if candidates:
		print (str(len(candidates)) + ' candidate(s) found: ')

		for c in candidates:
			print (c[1] + ': ' + c[0])
	else:
		print ('No candidates found.')
