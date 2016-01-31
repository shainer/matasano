#!/usr/bin/python

import encode_xor

if __name__ == '__main__':
	encoder = encode_xor.XOREncoder()
	text = 'Burning \'em, if you ain\'t quick and nimble\nI go crazy when I hear a cymbal'

	print(encoder.Encode(text, 'ICE'))
