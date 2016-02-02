"""
Decode an hexadecimal string that was XOR-encoded using a shorter key.
"""

import itertools
import fixed_xor
from plaintext_verifier import PlaintextVerifier

# I should really rewrite this in C++. If anyone is reading this
# code I am sorry.
import sys
sys.path.insert(0, '/home/shainer/source/matasano/lib')
import utils
import math

class XORDecoder(object):
	def __init__(self, key_length):
		"""Init the decoder with a specific key length."""
		self._key_length = key_length

		# Generates all the possible keys for the encoding, as
		# binary strings.
		self._all_keys = []
		for byte in map(''.join, itertools.product(
			'01', repeat=key_length)):
			self._all_keys.append(byte)

	def DecodeBin(self, encoded_string, frequency_only=False):
		"""Decodes a string represented in binary format.
		Returns a list of tuple. Each element contains a decoding we detected
		to likely be English plaintext, and the binary key used for that decoding.

		If frequency_only is True, only consider character frequency when deciding
		whether a string is English plaintext.

		Raises exceptions if the string is not in the expected format.
		"""
		decodings = []
		verifier = PlaintextVerifier()

		for key in self._all_keys:
			# Repeats the key as many time as necessary to produce a string
			# of the same length as the one we are decoding.
			fixed_key = key * int(len(encoded_string) / self._key_length)

			# Computes the XOR between the string and the key. The result
			# is again in binary form.
			decoded_bin = fixed_xor.fixed_xor_bins(fixed_key, encoded_string)
			ascii_candidate, is_valid_candidate = utils.bin_to_ascii(
				decoded_bin)

			if not is_valid_candidate:
				continue

			if frequency_only and verifier.CheckFrequency(ascii_candidate):
				decodings.append((ascii_candidate, key))
			elif not frequency_only and verifier.IsEnglishPlaintext(ascii_candidate):
				decodings.append((ascii_candidate, key))

		return decodings

	def DecodeHex(self, encoded_string, frequency_only=False):
		"""Decodes a string represented in hexadecimal ASCII format.
		Returns a list of tuple. Each element contains a decoding we detected
		to likely be English plaintext, and the binary key used for that decoding.

		Raises exceptions if the string is not in the expected format.
		"""
		bin_string = utils.hex_to_bin(encoded_string)
		return self.DecodeBin(bin_string, frequency_only)