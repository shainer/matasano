#!/usr/bin/python3

# Set 1, challenge 1: convert hex to base64.

from utils import encoding_utils as enclib

if __name__ == '__main__':
    b = enclib.HexToBase64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')
    expected = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

    if b == expected:
        print('Conversion from hex to base64 correct')
    else:
        print('Incorrect conversion from hex to base64. Got %s expected %s'
                % (b, expected))
