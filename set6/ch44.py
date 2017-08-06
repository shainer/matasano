#!/usr/bin/python3

import hashlib
import dsa
import rsa

# Set 6, challenge 44: DSA nonce recovery from repeated nonce.

# Parses the messages and other data into a list of dictionaries.
def ReadMessages(filename):
	content = None
	messages = []

	with open(filename, 'r') as f:
		content = f.readlines()

	message = {}
	num = 0

	for line in content:
		if line.startswith('msg: '):
			if message:
				messages.append(message)
				message = {}

			message['message'] = line[5:-1]
		elif line.startswith('s: '):
			message['s'] = int(line[3:-1])
		elif line.startswith('r: '):
			message['r'] = int(line[3:-1])
		elif line.startswith('m: '):
			message['m'] = line[3:-1]

	return messages

def BreakDSA(m1, m2, publicKey, dsa_params):
	# m1 and m2 are interchangeable, but if you compute m1['s'] - m2['s']
	# (and the rest accordingly), you get a negative K, which is not valid
	# according to the spec, and our implementation hangs trying to sign
	# a message.
	k = rsa.invmod((m2['s'] - m1['s']), dsa_params['Q'])
	k *= (int(m2['m'], 16) - int(m1['m'], 16))

	top = (m1['s'] * k) - int(m1['m'], 16)
	bottom = rsa.invmod(m1['r'], dsa_params['Q'])
	privateKey = (top * bottom) % dsa_params['Q']

	# Derive the public key from the private key and compare it
	# with the one we know.
	testPub = dsa.modexp(dsa_params['G'], privateKey, dsa_params['P'])
	if testPub == publicKey:
		print('[**] Success!')
		print('K:', k)
		print('X:', privateKey)

		# Sign one of the two messages with the private key and compare
		# the signature with the one we got from the file.
		sig = dsa.dsa_sign(dsa_params['Q'], dsa_params['P'], dsa_params['G'], privateKey,
						   int('0x' + m1['m'], 16), k=k)
		if sig == (m1['r'], m1['s']):
			print('[**] Broken private key passes validation')
			return True

	return False

if __name__ == '__main__':
	messages = ReadMessages('data/44.txt')

	publicKey = int('0x2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821', 16)

	dsa_params = {
    	'Q': int("0xf4f47f05794b256174bba6e9b396a7707e563c5b", 16),
    	'P': int("0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16),
    	'G': int("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", 16),
    }

	success = False

	# We simply try our break algorithm for every possible pair
	# of messages, since there are not that many.
	for i in range(0, len(messages)):
		for j in range(i + 1, len(messages)):
			m1 = messages[i]
			m2 = messages[j]

			if BreakDSA(m1, m2, publicKey, dsa_params):
				success = True
				break
		if success:
			break

	if not success:
		print('[!!] Failed breaking DSA')
