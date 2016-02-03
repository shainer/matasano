"""Utilities not related to a specific challenge."""

import base64

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
	
# TODO: enforce one naming convention.
def ReadableAscii(i):
	return (i == 10 or (i > 31 and i < 127))

def bin_to_ascii(bin_string):
	"""Returns a tuple of 2 elements: first one is the ASCII decoding of
	the binary string, second one is False if the decoding includes non-readable
	characters."""
	ascii = ''
	is_readable = True

	for i in range(0, len(bin_string) - 7, 8):
		# Derive individual "slices" of the string, 8 bits each.
		piece = bin_string[i:i+8]
		# Convert to an integer.
		num_piece = int(piece, base=2)

		if not ReadableAscii(num_piece):
			is_readable = False
		ascii += chr(num_piece)

	return (ascii, is_readable)

def base64_to_bin(text64):
	"""Converts a base64-encoded string into a binary string."""
	text = base64.b64decode(text64)
	bin_text = ''

	for ch in text:
		# We remove the leading '0b' added by bin()
		bin_ch = bin(ch)[2:]

		# Each 'ch' is a decimal ASCII character, so the resulting
		# binary number must have 8 digits. We pad with zeroes when
		# shorter.
		while len(bin_ch) < 8:
			bin_ch = '0' + bin_ch

		bin_text += bin_ch

	return bin_text

def base64_to_ascii(text64):
	"""Converts a base64-encoded string into an ASCII string."""
	text = base64.b64decode(text64)
	ascii_text = ''

	# The loop gives us the (decimal) ASCII number for each character,
	# so we only need to convert it to an actual character.
	for ch in text:
		ascii_text += chr(ch)

	return ascii_text

def ByteToPaddedBin(byte):
	"""Converts a byte to a binary string of length 8."""

	bin_str = '{0:b}'.format(byte)

	while len(bin_str) < 8:
		bin_str = '0' + bin_str

	return bin_str


def HammingDistance(b1, b2):
	"""Computes the Hamming distance between two binary strings.

	No verification is done on the strings (I am lazy), so use
	at your own risk.
	"""
	assert len(b1) == len(b2)
	distance = 0

	for i in range(len(b1)):
		if b1[i] != b2[i]:
			distance += 1

	return distance

def HammingDistanceAscii(s1, s2):
	"""Computes the Hamming distance between two ASCII strings."""
	assert len(s1) == len(s2)
	distance = 0

	for i in range(0, len(s1)):
		s1_byte = ord(s1[i])
		s2_byte = ord(s2[i])

		# Each byte is converted to binary; the resulting string
		# must have length 8 in order to preserve the ASCII
		# information, therefore we pad it.
		s1_bin = ByteToPaddedBin(s1_byte)
		s2_bin = ByteToPaddedBin(s2_byte)

		for j in range(0, len(s1_bin)):
			if s1_bin[j] != s2_bin[j]:
				distance += 1

	return distance