#!/usr/bin/python3

import random
import rsa

# Implements our "bad" server for the challenge. It stores all
# ciphertexts it sees and raises an error if asked to decrypt
# a ciphertext more than once.
class Oracle(object):
	def __init__(self, privateKey):
		self._past_ciphertexts = {}
		self._privateKey = privateKey

	def decrypt(self, ciphertext):
		if ciphertext in self._past_ciphertexts:
			raise ValueError('Ciphertext was already decrypted')

		self._past_ciphertexts[ciphertext] = True
		return rsa.Decrypt(self._privateKey, ciphertext)


# Taken from
# http://stackoverflow.com/questions/5486204/fast-modulo-calculations-in-python-and-ruby
# Required because any regular library blows up computing this with such huge numbers.
def modexp(g, u, p):
   """Computes s = (g ^ u) mod p
   Args are base, exponent, modulus
   (see Bruce Schneier's book, _Applied Cryptography_ p. 244)
   """
   s = 1
   while u != 0:
      if u & 1:
         s = (s * g) % p
      u >>= 1
      g = (g * g) % p
   return s

# Generates 5 different random numbers to run through this attack.
def GetCiphertexts(publicKey):
	plaintexts = set()
	ciphertexts = []

	while len(plaintexts) < 5:
		plaintexts.add(random.randint(0, 50))

	for pt in plaintexts:
		ciphertexts.append(rsa.Encrypt(publicKey, pt))

	print('My random messages:', plaintexts)
	return ciphertexts


# Modifies the ciphertext so that it is accepted by the oracle, but
# the plaintext can be recovered anyway.
def Hide(c, publicKey):
	e, n = publicKey
	s = 14  # random s > 1

	newCiphertext = (modexp(s, e, n) * c) % n
	return newCiphertext


# The opposite as Hide; it takes the plaintext as decrypted by
# the oracle and retrieves the one we meant.
def Reveal(text, publicKey):
	_, n = publicKey
	s = 14  # same as above

	# We are in modulo N group, so instead of dividing by n, we
	# need to multiply by its inverse in the group.
	inverse = rsa.invmod(s, n)
	return (text * inverse) % n


if __name__ == '__main__':
	publicKey, privateKey = rsa.GenerateRSAPair(61, 53)
	oracle = Oracle(privateKey)

	ciphertexts = GetCiphertexts(publicKey)

	plaintexts = [oracle.decrypt(ct) for ct in ciphertexts]
	print('I decrypted with the oracle:', plaintexts)

	newCiphertexts = [Hide(ct, publicKey) for ct in ciphertexts]
	# Without the hiding step, this would raise errors.
	intermediate = [oracle.decrypt(new) for new in newCiphertexts]

	plaintexts = [Reveal(i, publicKey) for i in intermediate]
	print('I decrypted by cheating the oracle:', plaintexts)
