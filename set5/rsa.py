#!/usr/bin/python3

from fractions import gcd
import gmpy2

def FindSmallerCoprime(n):
	for e in range(2, n):
		if gcd(n, e) == 1:
			return e

	raise ValueError('Could not find coprime')

def GenerateRSAPair():
	p = 61
	q = 53

	n = p * q
	totient =  n - (p + q - 1)
	e = FindSmallerCoprime(totient)
	d = gmpy2.invert(e, totient)

	return (e, n), (d, n)

def Encrypt(rsaKey, num):
	e, n = rsaKey
	return (num ** e) % n

def Decrypt(rsaKey, num):
	d, n = rsaKey
	return (num ** d) % n

if __name__ == '__main__':
	publicKey, privateKey = GenerateRSAPair()

	num = 42
	ciphertext = Encrypt(publicKey, num)

	if Decrypt(privateKey, ciphertext) == num:
		print('[**] Correct!')
	else:
		print('[!!] Your RSA pair is wrong.')