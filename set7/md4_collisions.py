#!/usr/bin/python3

import md4
import random

A0 = 0x67452301
B0 = 0xefcdab89
C0 = 0x98badcfe
D0 = 0x10325476
_BLOCK_SIZE = 16

def RandomOneBlockMessage():
	msg = b''

	for b in range(_BLOCK_SIZE):
		msg += b'\x00'
		#msg += bytearray([random.randint(0, 255)])

	return msg

def GetHash(m):
	md4 = md4.MD4()
	md4.update(m)
	return md4.digest()

def CompareHashes(m1, m2):
	return GetHash(m1) == GetHash(m2)

def leftRotate(n, amount):
	return ((n << amount) | ((n & 0xffffffff) >> (32 - amount))) & 0xffffffff

def F(x, y, z):
	return (x & y) | ((~x) & z)

def G(x, y, z):
	return (x & y) | (x & z) | (y & z)

def H(x, y, z):
	return x ^ y ^ z

def GetChainingVariables(m):
	X = m
	a, b, c, d, = [], [], [], []
	A, B, C, D = A0, B0, C0, D0
	a.append(A0)
	b.append(B0)
	c.append(C0)
	d.append(D0)

	AA, BB, CC, DD = A, B, C, D

	# Round 1
	A = leftRotate(A + F(B, C, D) + X[0], 3)
	D = leftRotate(D + F(A, B, C) + X[1], 7)
	C = leftRotate(C + F(D, A, B) + X[2], 11)
	B = leftRotate(B + F(C, D, A) + X[3], 19)
	a.append(A)
	b.append(B)
	c.append(C)
	d.append(D)

	A = leftRotate(A + F(B, C, D) + X[4], 3)
	D = leftRotate(D + F(A, B, C) + X[5], 7)
	C = leftRotate(C + F(D, A, B) + X[6], 11)
	B = leftRotate(B + F(C, D, A) + X[7], 19)
	a.append(A)
	b.append(B)
	c.append(C)
	d.append(D)

	A = leftRotate(A + F(B, C, D) + X[8], 3)
	D = leftRotate(D + F(A, B, C) + X[9], 7)
	C = leftRotate(C + F(D, A, B) + X[10], 11)
	B = leftRotate(B + F(C, D, A) + X[11], 19)
	a.append(A)
	b.append(B)
	c.append(C)
	d.append(D)

	A = leftRotate(A + F(B, C, D) + X[12], 3)
	D = leftRotate(D + F(A, B, C) + X[13], 7)
	C = leftRotate(C + F(D, A, B) + X[14], 11)
	B = leftRotate(B + F(C, D, A) + X[15], 19)
	a.append(A)
	b.append(B)
	c.append(C)
	d.append(D)

	# Round 2
	A = leftRotate(A + G(B, C, D) + X[0] + 0x5a827999, 3)
	D = leftRotate(D + G(A, B, C) + X[4] + 0x5a827999, 5)
	C = leftRotate(C + G(D, A, B) + X[8] + 0x5a827999, 9)
	B = leftRotate(B + G(C, D, A) + X[12] + 0x5a827999, 13)
	a.append(A)
	b.append(B)
	c.append(C)
	d.append(D)

	A = leftRotate(A + G(B, C, D) + X[1] + 0x5a827999, 3)
	D = leftRotate(D + G(A, B, C) + X[5] + 0x5a827999, 5)
	C = leftRotate(C + G(D, A, B) + X[9] + 0x5a827999, 9)
	B = leftRotate(B + G(C, D, A) + X[13] + 0x5a827999, 13)
	a.append(A)
	b.append(B)
	c.append(C)
	d.append(D)

	A = leftRotate(A + G(B, C, D) + X[2] + 0x5a827999, 3)
	D = leftRotate(D + G(A, B, C) + X[6] + 0x5a827999, 5)
	C = leftRotate(C + G(D, A, B) + X[10] + 0x5a827999, 9)
	B = leftRotate(B + G(C, D, A) + X[14] + 0x5a827999, 13)
	a.append(A)
	b.append(B)
	c.append(C)
	d.append(D)

	A = leftRotate(A + G(B, C, D) + X[3] + 0x5a827999, 3)
	D = leftRotate(D + G(A, B, C) + X[7] + 0x5a827999, 5)
	C = leftRotate(C + G(D, A, B) + X[11] + 0x5a827999, 9)
	B = leftRotate(B + G(C, D, A) + X[15] + 0x5a827999, 13)
	a.append(A)
	b.append(B)
	c.append(C)
	d.append(D)

	# Round 3
	A = leftRotate(A + H(B, C, D) + X[0] + 0x6ed9eba1, 3)
	D = leftRotate(D + H(A, B, C) + X[8] + 0x6ed9eba1, 9)
	C = leftRotate(C + H(D, A, B) + X[4] + 0x6ed9eba1, 11)
	B = leftRotate(B + H(C, D, A) + X[12] + 0x6ed9eba1, 15)
	a.append(A)
	b.append(B)
	c.append(C)
	d.append(D)

	A = leftRotate(A + H(B, C, D) + X[2] + 0x6ed9eba1, 3)
	D = leftRotate(D + H(A, B, C) + X[10] + 0x6ed9eba1, 9)
	C = leftRotate(C + H(D, A, B) + X[6] + 0x6ed9eba1, 11)
	B = leftRotate(B + H(C, D, A) + X[14] + 0x6ed9eba1, 15)
	a.append(A)
	b.append(B)
	c.append(C)
	d.append(D)

	A = leftRotate(A + H(B, C, D) + X[1] + 0x6ed9eba1, 3)
	D = leftRotate(D + H(A, B, C) + X[9] + 0x6ed9eba1, 9)
	C = leftRotate(C + H(D, A, B) + X[5] + 0x6ed9eba1, 11)
	B = leftRotate(B + H(C, D, A) + X[13] + 0x6ed9eba1, 15)
	a.append(A)
	b.append(B)
	c.append(C)
	d.append(D)

	A = leftRotate(A + H(B, C, D) + X[3] + 0x6ed9eba1, 3)
	D = leftRotate(D + H(A, B, C) + X[11] + 0x6ed9eba1, 9)
	C = leftRotate(C + H(D, A, B) + X[7] + 0x6ed9eba1, 11)
	B = leftRotate(B + H(C, D, A) + X[15] + 0x6ed9eba1, 15)
	a.append(A)
	b.append(B)
	c.append(C)
	d.append(D)

	return (a, b, c, d)

def bit(A, i):
	return (((A) >> ((i) - 1)) & 0x1)

def rrot(N, k):
	return (N & (2 ** (k+1)-1) << (32-k)) | (N >> k)

def lrot(X, i):
	return (((X) << (i)) | ((X) >> (32 - (i))))

def ApplyModifications(m):
	print(m)
	a, b, c, d = GetChainingVariables(m)
	newM = []

	# m[0] (a[1][7] = b[0][7])
	a[1] = a[1] ^ ((bit(a[1], 7) ^ bit(b[0], 7)) << 6)
	newM.append(rrot(a[1], 3) - a[0] - F(b[0], c[0], d[0]))

	# m[1]
	d[1] = d[1] & ~(1 << 6)
	newM.append(rrot(d[1], 7) - d[0] - F(a[1], b[0], c[0]))

	# m[2]
	c[1] = c[1] | (1 << 6)
	newM.append(rrot(c[1], 11) - c[0] - F(d[1], a[1], b[0]))

	# m[3]
	b[1] = c[1] | (1 << 6)
	newM.append(rrot(b[1], 19) - b[0] - F(c[1], d[1], a[1]))

	# m[4]
	a[2] = a[2] | (1 << 7)
	newM.append(rrot(a[2], 3) - a[1] - F(b[1], c[1], d[1]))

	# m[5]
	d[2] = d[2] & ~(1 << 13)
	newM.append(rrot(d[2], 7) - d[1] - F(a[2], b[1], c[1]))

	c[2] = c[2] ^ ((bit(c[2], 13) ^ bit(d[2], 13)) << 12) ^ (bit(c[2], 14) << 13) ^ ((bit(c[2], 15) ^ bit(d[2], 15)) << 14) ^ \
	       (bit(c[2], 19) << 18) ^ (bit(c[2], 20) << 19) ^ ((bit(c[2], 21) ^ 1) << 20) ^ (bit(c[2], 22) << 21)
	c[2] = c[2] ^ (bit(c[2], 17) << 16)	# extra conditions for c_(5, 26) 
	c[2] = c[2] ^ (bit(c[2], 18) << 17)	# extra conditions for c_(5, 27) 
	c[2] = c[2] ^ ((bit(c[2], 23) ^ 1) << 22)	# extra condition for c_(5, 29) 
	c[2] = c[2] ^ (bit(c[2], 31) << 30)	# extra conditions for d_(6, 29) 
	newM.append(rrot(c[2], 11) - c[1] - F(d[2], a[2], b[1]))

	b[2] = b[2] ^ ((bit(b[2], 13) ^ 1) << 12) ^ ((bit(b[2], 14) ^ 1) << 13) ^ (bit(b[2], 15) << 14) ^ ((bit(b[2], 17) ^ bit(c[2], 17)) << 16) ^ \
	       (bit(b[2], 19) << 18) ^ (bit(b[2], 20) << 19) ^ (bit(b[2], 21) << 20) ^ (bit(b[2], 22) << 21)
	b[2] = b[2] ^ (bit(b[2], 18) << 17)	# extra conditions for c_(5, 27) 
	b[2] = b[2] ^ ((bit(b[2], 31) ^ 1) << 30)	# extra conditions for d_(6, 29) 
	newM.append(rrot(b[2], 19) - b[1] - F(c[2], d[2], a[2]))

	a[3] = a[3] ^ ((bit(a[3], 13) ^ 1) << 12) ^ ((bit(a[3], 14) ^ 1) << 13) ^ ((bit(a[3], 15) ^ 1) << 14) ^ (bit(a[3], 17) << 16) ^ \
	       (bit(a[3], 19) << 18) ^ (bit(a[3], 20) << 19) ^ (bit(a[3], 21) << 20) ^ ((bit(a[3], 23) ^ bit(b[2], 23)) << 22) ^ \
	       ((bit(a[3], 22) ^ 1) << 21) ^ ((bit(a[3], 26) ^ bit(b[2], 26)) << 25)
	a[3] = a[3] ^ ((bit(a[3], 27) ^ bit(b[2], 27)) << 26)	# extra conditions for c_(6, 29) 
	newM.append(rrot(a[3], 3) - a[2] - F(b[2], c[2], d[2]))

	d[3] = d[3] ^ ((bit(d[3], 13) ^ 1) << 12) ^ ((bit(d[3], 14) ^ 1) << 13) ^ ((bit(d[3], 15) ^ 1) << 14) ^ (bit(d[3], 17) << 16) ^ \
	       (bit(d[3], 20) << 19) ^ ((bit(d[3], 21) ^ 1) << 20) ^ ((bit(d[3], 22) ^ 1) << 21) ^ (bit(d[3], 23) << 22) ^ \
	       ((bit(d[3], 26) ^ 1) << 25) ^ ((bit(d[3], 30) ^ bit(a[3], 30)) << 29)
	d[3] = d[3] ^ ((bit(d[3], 16) ^ 1) << 15)	# extra condition for b_(5, 29) 
	d[3] = d[3] ^ (bit(d[3], 19) << 18)	# extra condition for b_(5, 32) 
	d[3] = d[3] ^ (bit(d[3], 27) << 26)	# extra conditions for c_(6, 29) 
	newM.append(rrot(d[3], 7) - d[2] - F(a[3], b[2], c[2]))

	c[3] = c[3] ^ ((bit(c[3], 17) ^ 1) << 16) ^ (bit(c[3], 20) << 19) ^ (bit(c[3], 21) << 20) ^ (bit(c[3], 22) << 21) ^ (bit(c[3], 23) << 22) ^ \
	       (bit(c[3], 26) << 25) ^ ((bit(c[3], 30) ^ 1) << 29) ^ ((bit(c[3], 32) ^ bit(d[3], 32)) << 31)
	c[3] = c[3] ^ (bit(c[3], 16) << 15)	# extra condition for b_(5, 29) 
	c[3] = c[3] ^ ((bit(c[3], 19) ^ 1) << 18)	# extra condition for b_(5, 32) 
	c[3] = c[3] ^ (bit(c[3], 27) << 26)	# extra conditions for c_(6, 29) 
	newM.append(rrot(c[3], 11) - c[2] - F(d[3], a[3], b[2]))

	b[3] = b[3] ^ (bit(b[3], 20) << 19) ^ ((bit(b[3], 21) ^ 1) << 20) ^ ((bit(b[3], 22) ^ 1) << 21) ^ ((bit(b[3], 23) ^ bit(c[3], 23)) << 22) ^ \
	       ((bit(b[3], 26) ^ 1) << 25) ^ (bit(b[3], 30) << 29) ^ (bit(b[3], 32) << 31)
	b[3] = b[3] ^ (bit(b[3], 16) << 15)	# extra condition for b_(5, 29) 
	b[3] = b[3] ^ ((bit(b[3], 17) ^ 1) << 16)	# extra condition for b_(5, 30) 
	b[3] = b[3] ^ (bit(b[3], 19) << 18)	# extra condition for b_(5, 32) 
	b[3] = b[3] ^ ((bit(b[3], 27) ^ 1) << 26)	# extra conditions for c_(6, 29) 
	newM.append(rrot(b[3], 19) - b[2] - F(c[3], d[3], a[3]))

	a[4] = a[4] ^ (bit(a[4], 23) << 22) ^ (bit(a[4], 26) << 25) ^ ((bit(a[4], 27) ^ bit(b[3], 27)) << 26) ^ ((bit(a[4], 29) ^ bit(b[3], 29)) << 28) ^ \
	       ((bit(a[4], 30) ^ 1) << 29) ^ (bit(a[4], 32) << 31)
	a[4] = a[4] ^ ((bit(a[4], 20) ^ 1) << 19)	# extra condition for c_(5, 29) 
	a[4] = a[4] ^ (bit(a[4], 16) << 15)	# extra condition for b_(5, 29) 
	a[4] = a[4] ^ (bit(a[4], 17) << 16)	# extra condition for b_(5, 30) 
	a[4] = a[4] ^ (bit(a[4], 19) << 18)	# extra condition for b_(5, 32) 
	newM.append(rrot(a[4], 3) - a[3] - F(b[3], c[3], d[3]))

	d[4] = d[4] ^ (bit(d[4], 23) << 22) ^ (bit(d[4], 26) << 25) ^ ((bit(d[4], 27) ^ 1) << 26) ^ ((bit(d[4], 29) ^ 1) << 28) ^ (bit(d[4], 30) << 29) ^ \
	       ((bit(d[4], 32) ^ 1) << 31)
	d[4] = d[4] ^ ((bit(d[4], 20) ^ bit(a[4], 20)) << 19)	# extra condition for c_(5, 29) 
	d[4] = d[4] ^ ((bit(d[4], 16) ^ 1) << 15)	# extra condition for b_(5, 29) 
	d[4] = d[4] ^ ((bit(d[4], 17) ^ 1) << 16)	# extra condition for b_(5, 30) 
	d[4] = d[4] ^ ((bit(d[4], 19) ^ 1) << 18)	# extra condition for b_(5, 32) 
	newM.append(rrot(d[4], 7) - d[3] - F(a[4], b[3], c[3]))

	c[4] = c[4] ^ ((bit(c[4], 19) ^ bit(d[4], 19)) << 18) ^ ((bit(c[4], 23) ^ 1) << 22) ^ ((bit(c[4], 26) ^ 1) << 25) ^ (bit(c[4], 27) << 26) ^ \
	       (bit(c[4], 29) << 28) ^ (bit(c[4], 30) << 29)
	c[4] = c[4] ^ (bit(c[4], 20) << 19)	# extra condition for c_(5, 29) 
	newM.append(rrot(c[4], 11) - c[3] - F(d[4], a[4], b[3]))

	b[4] = b[4] ^ (bit(b[4], 19) << 18) ^ ((bit(b[4], 26) ^ 1) << 25) ^ ((bit(b[4], 27) ^ 1) << 26) ^ ((bit(b[4], 29) ^ 1) << 28) ^ (bit(b[4], 30) << 29) ^ \
	       ((bit(b[4], 32) ^ bit(c[4], 32)) << 31)
	b[4] = b[4] ^ ((bit(b[4], 20) ^ bit(d[4], 20)) << 19)	# extra condition for c_(5, 29) 
	newM.append(rrot(b[4], 19) - b[3] - F(c[4], d[4], a[4]))

	return [x + (2 ** 32) if x < 0 else x for x in newM]

if __name__ == '__main__':
	attempts = 0

	while True:
		attempts += 1
		m1 = RandomOneBlockMessage()
		newM = ApplyModifications(m1)
		print(newM)
		break

		# m2 = GenerateCollidingBlock(m1)
		# if CompareHashes(m1, m2):
		# 	print('[**] Success! Messages \"%s\" and \"%s\" have the same hash' % (m1, m2))
		# 	print('%d attempts were needed' % attempts)
		# 	break