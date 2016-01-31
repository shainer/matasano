#!/usr/bin/python

import base64
import binascii
import codecs

class Error(Exception):
	pass

class InvalidArgumentError(Error):
	pass


hex_to_bin_map = {'0': '0000',
			  	  '1': '0001',
			  	  '2': '0010',
			      '3': '0011',
			      '4': '0100',
			      '5': '0101',
			      '6': '0110',
			      '7': '0111',
			      '8': '1000',
			      '9': '1001',
			      'a': '1010',
			      'b': '1011',
			      'c': '1100',
			      'd': '1101',
			      'e': '1110',
			      'f': '1111'}
bin_to_hex_map = {'0000': '0',
			      '0001': '1',
			      '0010': '2',
			      '0011': '3',
			      '0100': '4',
			      '0101': '5',
			      '0110': '6',
			      '0111': '7',
			      '1000': '8',
			      '1001': '9',
			      '1010': 'a',
			      '1011': 'b',
			      '1100': 'c',
			      '1101': 'd',
			      '1110': 'e',
			      '1111': 'f'}

def hex_to_base64(hex_string):
	encoded = codecs.decode(hex_string, 'hex')
	return base64.b64encode(encoded)

def hex_to_bin(hex_string):
	"""Converts an hexadecimal string to the corresponding binary string."""
	res = ''

	for ch in hex_string:
		if ch not in hex_to_bin_map:
			raise InvalidArgumentError(
				"Called hex_to_bin with non-hex string: " + hex_string)

		res += hex_to_bin_map[ch]

	return res

def bin_to_hex(bin_string):
	"""Converts a binary string to the corresponding hexadecimal one."""
	res_hex = ''

	for i in range(0, len(bin_string) - 3, 4):
		piece = bin_string[i:i+4]
		if piece not in bin_to_hex_map:
			raise InvalidArgumentError(
				"Called bin_to_hex with non-bin string: " + bin_string)

		res_hex += bin_to_hex_map[piece]

	return res_hex

def fixed_xor(s1, s2):
	"""Computes the fixed XOR between two hexadecimal strings."""
	if len(s1) != len(s2):
		raise InvalidArgumentError(
			"Tried to compute fixed XOR between strings of different length")

	b1 = hex_to_bin(s1)
	b2 = hex_to_bin(s2)
	res_b = ''

	for i in range(0, len(b1)):
		if b1[i] == b2[i]:
			res_b += '0'
		else:
			res_b += '1'

	return bin_to_hex(res_b)

def fixed_xor_bins(b1, b2):
	if len(b1) != len(b2):
		raise InvalidArgumentError(
			"Tried to compute fixed XOR between strings of different length")
	res_b = ''

	for i in range(0, len(b1)):
		if b1[i] == b2[i]:
			res_b += '0'
		else:
			res_b += '1'

	return res_b

if __name__ == '__main__':
	b = hex_to_base64(
		'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')
	print(b)

	b = fixed_xor('1c0111001f010100061a024b53535009181c',
		'686974207468652062756c6c277320657965')
	print (b)

