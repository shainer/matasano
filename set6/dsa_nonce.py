#!/usr/bin/python3

import hashlib
import dsa
import rsa

def HashMessage(messageBytes):
	"""Computes a SHA1 of a message, expressed a bytes,
	and converts the digest to an integer. This makes it
	suitable to be signed/verified by DSA.
	"""
	m = hashlib.sha1()
	m.update(messageBytes)
	digest = m.hexdigest()

	H = int('0x' + digest, 16)
	return H

# Finds the solution in around 16 seconds.
def BreakDSA(p, g, q, r, s):
	publicKey = int('0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17', 16)

	m = hashlib.sha1()
	H = HashMessage(b'For those that envy a MC it can be hazardous to your health\n'
			        b'So be friendly, a matter of life and death, just like a etch-a-sketch\n')

	k = 0
	brokenKey = None

	for k in range(1, 2 ** 16 + 1):
		top = (s * k) - H
		bottom = rsa.invmod(r, q)
		privateKey = (top * bottom) % q

		# Derive the public key from the private key and compare it
		# with the one we know.
		testPub = dsa.modexp(g, privateKey, p)
		if testPub == publicKey:
			brokenKey = privateKey
			break
	else:
		print('[!!] Unable to break private key')
		return

	print('[**] Success!')
	print('K:', k)
	print('X:', brokenKey)
	return brokenKey, k
	

if __name__ == '__main__':
	message = b'For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n'
	r = 548099063082341131477253921760299949438196259240
	s = 857042759984254168557880549501802188789837994940

	dsa_params = {
    	'Q': int("0xf4f47f05794b256174bba6e9b396a7707e563c5b", 16),
    	'P': int("0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16),
    	'G': int("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", 16),
    }

    # To verify we have found the right k and private key, we sign the same message
    # using both of them. If the signatures match with the one we got from the
    # challenge, it is correct.
	brokenKey, brokenK = BreakDSA(dsa_params['P'], dsa_params['G'], dsa_params['Q'], r, s)
	sig = dsa.dsa_sign(dsa_params['Q'], dsa_params['P'], dsa_params['G'], brokenKey,
					   HashMessage(message), k=brokenK)

	if sig == (r, s):
		print('[**] The signatures (with real and broken private key) match!')
	else:
		print('[!!] The signatures (with real and broken private key) do not match!')
