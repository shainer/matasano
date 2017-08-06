#!/usr/bin/python3

from Crypto.Cipher import AES
from Crypto.Cipher import Blowfish
import math
import itertools
from ch52 import *

def F(message):
	return MerkleDamgard(padPKCS7(message), state=b'\x07\x87', stateLen=2)

# This is a MD construction like in F, but with a larger state length,
# different initial state, and Blowfish instead of AES.
def G(message, state=b'\x00\x00', stateLen=3):
	newState = state
	newState = padPKCS7(newState)

	for i in range(GetNumBlocks(message)):
		cipher = Blowfish.new(newState, Blowfish.MODE_ECB)
		newState = cipher.encrypt(GetBlock(message, i))
		newState = padPKCS7(newState[:stateLen])

	return newState[:stateLen]

def H(message):
	return F(message) + G(message)

# Takes a list of collisions and returns those that are collisions in G
# too.
def FindGCollisions(collisions):
	hashDict = {}
	newCollisions = []

	for c in collisions:
		h = G(c)

		if h not in hashDict:
			hashDict[h] = [c]
		else:
			hashDict[h].append(c)

	for k in hashDict:
		if len(hashDict[k]) > 1:
			newCollisions.extend(hashDict[k])

	return newCollisions

if __name__ == '__main__':
	stateLen = 2

	# This finds a good number of collisions in G (and therefore H).
	collisions = FindCollisions(stateLen, 8192, b'\x07\x87')
	print('Found %d collisions for F' % len(collisions))

	if not VerifyCollisions(collisions, b'\x07\x87'):
		print('!! Error')
	else:
		hCollisions = FindGCollisions(collisions)

		if len(hCollisions) > 0:
			print('[**] Found collisions for both F and G:', hCollisions)
		else:
			print('[**] Collisions were only valid for F')
