# Thanks to http://www.acooke.org/cute/PurePython0.html for
# this part.

#!/usr/bin/python3

import binascii
from array import array
from struct import pack, unpack

def _pad(msg, fakeLen):
	n = len(msg) if fakeLen is None else fakeLen
	bit_len = n * 8
	index = (bit_len >> 3) & 0x3f

	pad_len = 120 - index
	if index < 56:
		pad_len = 56 - index
	
	padding = b'\x80' + b'\x00'*63
	padded_msg = msg + padding[:pad_len] + pack('<Q', bit_len)
	return padded_msg

def _left_rotate(n, b):
	return ((n << b) | ((n & 0xffffffff) >> (32 - b))) & 0xffffffff

def _f(x, y, z): return x & y | ~x & z
def _g(x, y, z): return x & y | x & z | y & z
def _h(x, y, z): return x ^ y ^ z

def _f1(a, b, c, d, k, s, X): return _left_rotate(a + _f(b, c, d) + X[k], s)
def _f2(a, b, c, d, k, s, X): return _left_rotate(a + _g(b, c, d) + X[k] + 0x5a827999, s)
def _f3(a, b, c, d, k, s, X): return _left_rotate(a + _h(b, c, d) + X[k] + 0x6ed9eba1, s)

# Implementation of MD4 hashing.
class MD4:
	def __init__(self, internalState=None):
		if internalState is None:
			self.A = 0x67452301
			self.B = 0xefcdab89
			self.C = 0x98badcfe
			self.D = 0x10325476
		else:
			self.A = internalState[0]
			self.B = internalState[1]
			self.C = internalState[2]
			self.D = internalState[3]

	def update(self, message_string, fakeLen=None):
		msg_bytes = _pad(message_string, fakeLen)
		for i in range(0, len(msg_bytes), 64):
			self._compress(msg_bytes[i:i+64])

	def _compress(self, block):
		a, b, c, d = self.A, self.B, self.C, self.D

		x = []
		for i in range(0, 64, 4):
			x.append(unpack('<I', block[i:i+4])[0])

		a = _f1(a,b,c,d, 0, 3, x)
		d = _f1(d,a,b,c, 1, 7, x)
		c = _f1(c,d,a,b, 2,11, x)
		b = _f1(b,c,d,a, 3,19, x)
		a = _f1(a,b,c,d, 4, 3, x)
		d = _f1(d,a,b,c, 5, 7, x)
		c = _f1(c,d,a,b, 6,11, x)
		b = _f1(b,c,d,a, 7,19, x)
		a = _f1(a,b,c,d, 8, 3, x)
		d = _f1(d,a,b,c, 9, 7, x)
		c = _f1(c,d,a,b,10,11, x)
		b = _f1(b,c,d,a,11,19, x)
		a = _f1(a,b,c,d,12, 3, x)
		d = _f1(d,a,b,c,13, 7, x)
		c = _f1(c,d,a,b,14,11, x)
		b = _f1(b,c,d,a,15,19, x)

		a = _f2(a,b,c,d, 0, 3, x)
		d = _f2(d,a,b,c, 4, 5, x)
		c = _f2(c,d,a,b, 8, 9, x)
		b = _f2(b,c,d,a,12,13, x)
		a = _f2(a,b,c,d, 1, 3, x)
		d = _f2(d,a,b,c, 5, 5, x)
		c = _f2(c,d,a,b, 9, 9, x)
		b = _f2(b,c,d,a,13,13, x)
		a = _f2(a,b,c,d, 2, 3, x)
		d = _f2(d,a,b,c, 6, 5, x)
		c = _f2(c,d,a,b,10, 9, x)
		b = _f2(b,c,d,a,14,13, x)
		a = _f2(a,b,c,d, 3, 3, x)
		d = _f2(d,a,b,c, 7, 5, x)
		c = _f2(c,d,a,b,11, 9, x)
		b = _f2(b,c,d,a,15,13, x)

		a = _f3(a,b,c,d, 0, 3, x)
		d = _f3(d,a,b,c, 8, 9, x)
		c = _f3(c,d,a,b, 4,11, x)
		b = _f3(b,c,d,a,12,15, x)
		a = _f3(a,b,c,d, 2, 3, x)
		d = _f3(d,a,b,c,10, 9, x)
		c = _f3(c,d,a,b, 6,11, x)
		b = _f3(b,c,d,a,14,15, x)
		a = _f3(a,b,c,d, 1, 3, x)
		d = _f3(d,a,b,c, 9, 9, x)
		c = _f3(c,d,a,b, 5,11, x)
		b = _f3(b,c,d,a,13,15, x)
		a = _f3(a,b,c,d, 3, 3, x)
		d = _f3(d,a,b,c,11, 9, x)
		c = _f3(c,d,a,b, 7,11, x)
		b = _f3(b,c,d,a,15,15, x)

		# update state
		self.A = (self.A + a) & 0xffffffff
		self.B = (self.B + b) & 0xffffffff
		self.C = (self.C + c) & 0xffffffff
		self.D = (self.D + d) & 0xffffffff
		# print("Current state is ")
		# print(self.A)
		# print(self.B)
		# print(self.C)
		# print(self.D)

	def digest(self):
		return binascii.hexlify(pack('<IIII', self.A, self.B, self.C, self.D))