import base64
import codecs

# These should not be accessed externally.
HEX_TO_BIN_MAP = {'0': '0000',
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
BIN_TO_HEX_MAP = {'0000': '0',
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

class Error(Exception):
	pass

class InvalidArgumentError(Error):
	pass


# TODO: do this by hand.
def HexToBase64(hex_string):
    encoded = codecs.decode(hex_string, 'hex')
    return base64.b64encode(encoded)


def HexToBin(hex_string):
	"""Converts an hexadecimal string to the corresponding binary string."""
	res = ''

	for ch in hex_string:
		if ch not in HEX_TO_BIN_MAP:
			raise InvalidArgumentError(
				'Called HexToBin with non-hex string: ' + hex_string)

		res += HEX_TO_BIN_MAP[ch]

	return res

def BinToHex(bin_string):
	"""Converts a binary string to the corresponding hexadecimal one."""
	res_hex = ''

	# Divides the string in pieces of 4 characters each, then converts
	# each piece to an hexadecimal character.
	#
	# If the length of the input string is not divisible by 4, the last
	# bits will be ignored.
	for i in range(0, len(bin_string) - 3, 4):
		piece = bin_string[i:i+4]
		if piece not in BIN_TO_HEX_MAP:
			raise InvalidArgumentError(
				"Called BinToHex with non-bin string: " + bin_string)

		res_hex += BIN_TO_HEX_MAP[piece]

	return res_hex