#!/usr/bin/python3

import math
import rsa

def BreakRSA(C, N):
	n12 = N[1] * N[2]
	n02 = N[0] * N[2]
	n01 = N[0] * N[1]
	n012 = N[0] * N[1] * N[2]

	# Using the Chinese Remainder Theorem we can decompose C and N.
	r0 = C[0] * n12 * rsa.invmod(n12, N[0])
	r1 = C[1] * n02 * rsa.invmod(n02, N[1])
	r2 = C[2] * n01 * rsa.invmod(n01, N[2])

	res = r0 + r1 + r2
	res = res % n012

	# Compute the cube root and round to the nearest integer.
	return round(res ** (1.0 / 3.0))


if __name__ == '__main__':
	publicKey1, _ = rsa.GenerateRSAPairBroadcast(31, 7)
	publicKey2, _ = rsa.GenerateRSAPairBroadcast(17, 13)
	publicKey3, _ = rsa.GenerateRSAPairBroadcast(37, 11)

	# We encrypt the same plaintext with three different public keys, all
	# of which use E=3 internally.
	num = 42
	c1 = rsa.Encrypt(publicKey1, num)
	c2 = rsa.Encrypt(publicKey2, num)
	c3 = rsa.Encrypt(publicKey3, num)

	recoveredPt = BreakRSA([c1, c2, c3], [publicKey1[1], publicKey2[1], publicKey3[1]])
	if recoveredPt == num:
		print('[**] Correct!')
	else:
		print('[!!] Failed.')