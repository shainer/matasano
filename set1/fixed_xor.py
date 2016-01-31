#!/usr/bin/python

"""
Contains implementations of fixed XOR and a few other utilities.
"""

# I should really rewrite this in C++. If anyone is reading this
# code I am sorry.
import sys
sys.path.insert(0, '/home/shainer/source/matasano/lib')
import utils

import base64

class Error(Exception):
	pass

class InvalidArgumentError(Error):
	pass


def hex_to_base64(hex_string):
	encoded = codecs.decode(hex_string, 'hex')
	return base64.b64encode(encoded)

def fixed_xor(s1, s2):
	"""Computes the fixed XOR between two hexadecimal strings."""
	try:
		b1 = utils.hex_to_bin(s1)
		b2 = utils.hex_to_bin(s2)
		res_b = fixed_xor_bins(b1, b2)
	except utils.InvalidArgumentError as err:
		# Raise again as an error of this module for better clarity.
		raise InvalidArgumentError(err)

	return utils.bin_to_hex(res_b)

def fixed_xor_bins(b1, b2):
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

