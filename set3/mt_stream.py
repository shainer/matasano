#!/usr/bin/python3

import random
import time
from mersenne_twister import MersenneTwister

def BlockXor(completeText, stream):
	"""Quick XOR between two bytes."""
	assert len(completeText) == len(stream)

	res = b''
	streamIndex = 0

	for ch in completeText:
		res += bytes([ch ^ stream[streamIndex]])
		streamIndex += 1

	return res

def MtStream(textLen, seed):
	"""Generates the stream of random bytes."""
	generator = MersenneTwister(seed)
	stream = []

	for i in range(0, textLen):
		stream.append(generator.randomNumber() % (2 ** 8))

	return stream

def EncryptMt(plaintext, seed):
	prepend = b'Y' * random.randint(1, 10)
	completeText = prepend + plaintext

	stream = MtStream(len(completeText), seed)
	return BlockXor(completeText, stream)

if __name__ == '__main__':
	plaintext = b'X' * 14
	maxSeed = 65535  # 16-bit seed.
	seed = random.randint(0, maxSeed)

	# Useful to verify we got it right :)
	print ('[**] The random seed is ' + str(seed))
	ciphertext = EncryptMt(plaintext, seed)

	# How many characters in the ciphertext are random characters that
	# were prepended. We pretend we do not know what these characters
	# are.
	randomLen = len(ciphertext) - 14
	internalState = []

	# This gives the generated random numbers from randomLen on; we
	# cannot retrieve the first ones because we do not know the
	# associated plaintext characters.
	for ch in range(randomLen, len(ciphertext)):
		internalState += BlockXor(bytes([ciphertext[ch]]), b'X')

	# For each possible seed, we build a MT random generator, generate
	# numbers and compare them with the retrieve internal state. If
	# they match, we found the right seed. This takes at most 1-2 minutes
	# when the random seed is close to maxSeed.
	#
	# TODO: find a more efficient cracking way than bruteforce.
	for probableSeed in range(0, maxSeed):
		mt = MersenneTwister(probableSeed)

		reproducedState = []
		for i in range(0, len(ciphertext)):
			reproducedState.append(mt.randomNumber() % (2 ** 8))

		if reproducedState[randomLen:] == internalState:
			print('[**] The cracked seed is: ', str(probableSeed))
			break
	else:
		print('[!!] Could not crack seed.')