"""Utilities not related to a specific challenge."""


class Error(Exception):
	pass

class InvalidArgumentError(Error):
	pass


# These should not be accessed externally.
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

	# Divides the string in pieces of 4 characters each, then converts
	# each piece to an hexadecimal character.
	#
	# If the length of the input string is not divisible by 4, the last
	# bits will be ignored.
	for i in range(0, len(bin_string) - 3, 4):
		piece = bin_string[i:i+4]
		if piece not in bin_to_hex_map:
			raise InvalidArgumentError(
				"Called bin_to_hex with non-bin string: " + bin_string)

		res_hex += bin_to_hex_map[piece]

	return res_hex
	