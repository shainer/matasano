import sys
from utils import encoding_utils as enclib

class XOREncoder(object):

	def _ByteToPaddedBin(self, byte):
		bin_str = '{0:b}'.format(byte)

		while len(bin_str) < 8:
			bin_str = '0' + bin_str

		return bin_str

	def _DoEncode(self, text, key):
		"""Computes the XOR between a text and a key. Both are expressed
		as list of ASCII characters.

		The text length is assumed to be a multiple of the key length;
		the key length is extended accordingly if shorted.

		Returns the encoded string as a binary string.
		"""
		text_bin = ''
		key_bin = ''

		for i in range(0, len(text)):
			text_byte = ord(text[i])
			key_byte = ord(key[i % len(key)])

			text_bin += self._ByteToPaddedBin(text_byte)
			key_bin += self._ByteToPaddedBin(key_byte)
		
		res_bin = ''

		for j in range(0, len(text_bin)):
			if text_bin[j] == key_bin[j]:
				res_bin += '0'
			else:
				res_bin += '1'

		return res_bin

	def Encode(self, text, key):
		"""The result is the string as hexadecimals."""
		bin_result = self._DoEncode(text, key)
		return enclib.BinToHex(bin_result)

	def EncodeAsAscii(self, text, key):
		"""The result is an ASCII string."""
		bin_result = self._DoEncode(text, key)
		ascii_result = enclib.BinToAscii(bin_result)

		# Output is not ASCII readable, discarding the result.
		if not ascii_result[1]:
			return ''

		return ascii_result[0]