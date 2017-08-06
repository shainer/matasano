#!/usr/bin/python3

# RSA implementation, taken from set 5.

import random
from utils import modexp
from primes import getProbablePrime

# Computes the GCD between two numbers using the extended Euclidean formulation.
# This means we find solutions to this equation:
#  a*x + b*y = gcd(x, y)
# and we return a tuple with the gcd, x and y in this order.
#
# We take two integers, a and b, which we assume positive. We compute a/b and store
# the integer quotient and remainder. Then we do the same with the quotient and
# remainder. This produces a strictly decreasing sequence of remainders, which
# terminates at 0; the last nonzero remainder in the sequence is the GCD.
#
# This works because if a = bq + r, then gcd(a, b) = gcd(b, r). At the last step
# we get gcd(r, r) = r.
def egcd(a, b):
    lastremainder, remainder = abs(a), abs(b)
    x, lastx, y, lasty = 0, 1, 1, 0

    while remainder:
    	# divmod was introduced in Python 3, and returns both the quotient
    	# and remainder of an integer division, in a tuple.
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient*x, x
        y, lasty = lasty - quotient*y, y

    return lastremainder, lastx, lasty

# Computes the modular multiplicative inverse of a, with modulo m. This is an
# integer x such that ax = 1 (mod m), that is the inverse of a in the
# ring of integers modulo m, called Zm.
# Such an inverse exists only if a and m are coprime, so their gcd is 1.
#
# Let's see how to use the extended Euclidean algortihm to find the invmod.a
# We find solutions to the Bezout's identity:
#  ax + by = gcd(a, b)
# If ax = 1 (mod m), this implies that m is a divisor of ax-1. Therefore:
#  ax - 1 = qm
#  ax - qm = 1
# This is the same equation solved by the extended Euclidean, but we know
# the gcd already, since we say it must be 1.
def invmod(a, m):
	g, x, y = egcd(a, m)
	if g != 1:
	    raise ValueError('modular inverse does not exist')
	else:
	    return x % m

def FindSmallerCoprime(n):
	for e in range(2, n):
		gcd = egcd(n, e)
		if gcd[0] == 1:
			return e

	raise ValueError('Could not find coprime')

def GenerateRSAPair(keysize):
	"""Generates a RSA key pair given the size in bits."""
	e = 3  # we know this is not a good choice, but it works here :D
	bitcount = (keysize + 1) // 2 + 1

	p = 7
	while (p - 1) % e == 0:
 		p = getProbablePrime(bitcount)

	q = p
	while q == p or (q - 1) % e == 0:
		q = getProbablePrime(bitcount)

	n = p * q
	et = (p - 1) * (q - 1)
	d = invmod(e, et)
	return ((e, n), (d, n))

def Encrypt(rsaKey, num):
	e, n = rsaKey
	return modexp(num, e, n)

def Decrypt(rsaKey, num):
	d, n = rsaKey
	return modexp(num, d, n)

if __name__ == '__main__':
	publicKey, privateKey = GenerateRSAPair(1024)

	num = 42
	ciphertext = Encrypt(publicKey, num)

	if Decrypt(privateKey, ciphertext) == num:
		print('[**] Correct!')
	else:
		print('[!!] Your RSA pair is wrong.')
