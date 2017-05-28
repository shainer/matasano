#!/usr/bin/python3

# Set 1, challenge 5: implement repeating-key XOR

import encode_xor

if __name__ == '__main__':
	encoder = encode_xor.XOREncoder()
	text = ('Burning \'em, if you ain\'t quick and nimble\n'
	 	    'I go crazy when I hear a cymbal')

	res = encoder.Encode(text, 'ICE')
	expected = ('0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a'
				'26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027'
				'630c692b20283165286326302e27282f')

	if res == expected:
		print('XOR encoding correct')
	else:
		print('XOR encoding incorrect. Got %s expected %s' % (res, expected))