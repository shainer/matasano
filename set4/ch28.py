#!/usr/bin/python3

import struct
import hashlib

# Set 4, challenge 28: implement a SHA-1 keyed MAC.

# Based on the pseudocode on the Wikipedia page:
# https://en.wikipedia.org/wiki/SHA-1#SHA-1_pseudocode
class Sha1Hash(object):
	# Allows to inject a h vector, for length-extension attacks.
	def __init__(self, initial_h=None):
		self._h = initial_h

	def _leftRotate(self, n, bits):
		"""Rotates a 32-bit integer by |bits| bits."""
		return ((n << bits) | (n >> (32 - bits))) & 0xffffffff

	def _processChunk(self, chunk):
		"""Processes a single chunk of 64 bytes, updating the
		internal state accordingly."""
		assert len(chunk) == 64

		words = [0] * 80
		# Break chunk into sixteen 4-byte big-endian words w[i]
		for i in range(16):
			words[i] = struct.unpack(b'>I', chunk[i*4:i*4 + 4])[0]

		# Extend the sixteen 4-byte words into eighty 4-byte words:
		for i in range(16, 80):
			words[i] = self._leftRotate(
				words[i-3] ^ words[i-8] ^ words[i-14] ^ words[i-16], 1)

		a = self._h[0]
		b = self._h[1]
		c = self._h[2]
		d = self._h[3]
		e = self._h[4]

		for i in range(0, 80):
			if i >= 0 and i <= 19:
				f = (b & c) | ((~b) & d)
				k = 0x5A827999
			elif i >= 20 and i <= 39:
				f = b ^ c ^ d
				k = 0x6ED9EBA1
			elif i >= 40 and i <= 59:
				f = (b & c) | (b & d) | (c & d) 
				k = 0x8F1BBCDC
			else:
				f = b ^ c ^ d
				k = 0xCA62C1D6

			tmp = ((self._leftRotate(a, 5) + f + e + k + words[i])
				    & 0xffffffff)
			e = d
			d = c
			c = self._leftRotate(b, 30)
			b = a
			a = tmp

		self._h[0] = (self._h[0] + a) & 0xffffffff
		self._h[1] = (self._h[1] + b) & 0xffffffff
		self._h[2] = (self._h[2] + c) & 0xffffffff
		self._h[3] = (self._h[3] + d) & 0xffffffff
		self._h[4] = (self._h[4] + e) & 0xffffffff

	# Computes the SHA1 digest of inputBytes. For length-extension attacks,
	# we may want to inject the message length. Otherwise, we use the legit
	# length of the input.
	def digest(self, inputBytes, fakeLen=None):
		"""Computes the digest of a message, stored in inputBytes."""
		# Initial state.
		if self._h is None:
			self._h = [
				0x67452301,
				0xEFCDAB89,
				0x98BADCFE,
				0x10325476,
				0xC3D2E1F0,
			]

		message = inputBytes
		byteLength = len(message) if fakeLen is None else fakeLen

		# Appends the bit '1' to the message.
		message += b'\x80'
		# Appends the byte '0' k times; k is such that the resulting
		# message length in bits is congruent to 64.
		message += b'\x00' * ((56 - (byteLength + 1) % 64) % 64)
		# Appends the message length in bits as a 64-bit big-endian
		# integer (Q is unsigned long long for the struct module).
		message += struct.pack(b'>Q', byteLength * 8)

		# Processes each 64-bytes chunk separately.
		for i in range(0, int(len(message) / 64)):
			chunk = message[i * 64 : (i+1) * 64]
			self._processChunk(chunk)

		# Final digest.
		digest = (self._h[0] << 128) | (self._h[1] << 96) | (self._h[2] << 64) | (self._h[3] << 32) | self._h[4]
		return '%x' % digest  # convert to hex string as most digests.


def Sha1Sign(message):
	"""Signs the message with SHA1 and a secret prefix.
	Both the input and output are byte strings."""
	mac = b'YELLOW SUBMARINE' + message
	h = Sha1Hash()
	return h.digest(mac)

def Sha1SignWithLib(message):
	sha = hashlib.sha1()
	sha.update(b'YELLOW SUBMARINE')
	sha.update(message)
	return sha.hexdigest()

if __name__ == '__main__':
	text = b'some random text here'

	# Simple comparison to show that we produce the same result
	# as the standard library implementation.
	mac1 = Sha1Sign(text)
	mac2 = Sha1SignWithLib(text)

	print(mac1)
	print(mac2)
