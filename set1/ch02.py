#!/usr/bin/python3

# Set 1, challenge 2: fixed XOR.

from utils import encoding_utils as enclib

class Error(Exception):
	pass

class InvalidArgumentError(Error):
	pass


def FixedXORBins(b1, b2):
	"""Computes the fixed XOR between two binary strings."""

	if len(b1) != len(b2):
		raise InvalidArgumentError(
			"Tried to compute fixed XOR between strings of different length.")
	res_b = ''

	for i in range(0, len(b1)):
		# Not a binary digit.
		if b1[i] not in ('0', '1') or b2[i] not in ('0', '1'):
			raise InvalidArgumentError(
				"Tried to compute binary XOR between non-binary strings.")

		if b1[i] == b2[i]:
			res_b += '0'
		else:
			res_b += '1'

	return res_b


def FixedXOR(s1, s2):
	"""Computes the fixed XOR between two hexadecimal strings."""
	try:
		b1 = enclib.HexToBin(s1)
		b2 = enclib.HexToBin(s2)
		res_b = FixedXORBins(b1, b2)
	except enclib.InvalidArgumentError as err:
		# Raise again as an error of this module for better clarity.
		raise InvalidArgumentError(err)

	return enclib.BinToHex(res_b)


if __name__ == '__main__':
    s1 = '1c0111001f010100061a024b53535009181c'
    s2 = '686974207468652062756c6c277320657965'
    expected = '746865206b696420646f6e277420706c6179'
    res = FixedXOR(s1, s2)

    if res == expected:
        print('Fixed XOR correct')
    else:
        print('Fixed XOR incorrect: got %s expected %s'
                % (res, expected))
