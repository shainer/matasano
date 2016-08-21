#!/usr/bin/python3

# Set of utilities for generating prime numbers for RSA
# key generation.

# Taken from https://github.com/akalin/cryptopals-python3

import random

smallPrimes = [2, 3, 5, 7, 11, 13, 17, 19]

def hasSmallPrimeFactor(p):
    for x in smallPrimes:
        if p % x == 0:
            return True
    return False

def isProbablePrime(p, n):
    for i in range(n):
        a = random.randint(1, p)
        if pow(a, p - 1, p) != 1:
            return False
    return True

def getProbablePrime(bitcount):
	"""Get prime numbers that are represented by |bitcount| bits.
	They are prime with a good probability, but not 100 percent certainty.
	"""
	while True:
		p = random.randint(2**(bitcount - 1), 2**bitcount - 1)
		if not hasSmallPrimeFactor(p) and isProbablePrime(p, 5):
			return p