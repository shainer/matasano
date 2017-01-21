#!/usr/bin/python3

from Crypto.Cipher import AES
import math
import itertools

def padPKCS7(message, k=16):
	"""Usual PKCS#7 padding."""
	if len(message) % k == 0:
		return message

	ch = k - (len(message) % k)
	return message + bytes([ch] * ch)

def GetNumBlocks(message):
	return math.ceil(len(message) / AES.block_size)

def GetBlock(message, index):
	# To make it easier, I assume there are always perfectly-sized blocks
	# in the input.
	return message[index * AES.block_size:(index+1) * AES.block_size]

def GenerateAllCollisions(perStageCollisions, result, i=0, partial=b''):
	if i >= len(perStageCollisions):
		result.append(partial)
		return

	for piece in perStageCollisions[i]:
		newPartial = partial + piece
		GenerateAllCollisions(perStageCollisions, result, i+1, newPartial)

def MerkleDamgard(message, state=b'I\xbf', stateLen=2):
	"""Applies an arbitrary Merkle-Damgard construction to the message.

	The default state length and initial state are those used all over
	this program.
	"""
	newState = state
	# The state length we use is shorter than what AES wants for the keys.
	newState = padPKCS7(newState)

	for i in range(GetNumBlocks(message)):
		cipher = AES.new(newState, AES.MODE_ECB)
		newState = cipher.encrypt(GetBlock(message, i))

		# This would be a really bad idea to do in practice, if we are
		# actually using AES or an algorithm that requires keys of
		# a certain size. It's needed here because the hash and
		# the key needs to be the same for the challenge to work, and
		# the hash we return has 2 bytes.
		newState = padPKCS7(newState[:stateLen])

	return newState[:stateLen]

def FindCollisionOneStage(allPossibleBlocks, initialState):
	"""This finds collisions in one stage of the MD construction.

	This means that given all possible blocks of size 16 bytes, and
	an initial state, we look for two blocks that are hashed to the
	same sequence. The initial state is the actual initial state for
	the first block, and the colliding hash of the previous stage
	for next ones.

	Given the short size of hashes, we can brute-force this; there
	are only (2^8) possible blocks.
	"""
	hashDict = {}
	collisions = []

	for b in allPossibleBlocks:
		b = padPKCS7(b)
		h = MerkleDamgard(b, initialState)

		if h in hashDict:
			collisions.append(b)
			collisions.append(hashDict[h])
			# Return both the hash and the list of colliding blocks.
			return (h, collisions)
		else:
			hashDict[h] = b

	# Nothing found.
	return (b'', collisions)

def FindCollisions(stateLen, n, initialState):
	"""Finds n collisions for the given hashing functions.

	- statelen is the length of the hashes.
	- n is the number of collisions we want to find. It works better when it's
	a power of 2.
	"""
	# Prepare by generating all possible blocks, i.e. all possible
	# byte strings of 16 bytes. We use this inside FindCollisionOneStage, but
	# we only generate it once here.
	allBytes = range(2 ** 8)
	allPossibleBlocks = []
	for comb in itertools.combinations(allBytes, stateLen):
		byteString = b''.join(x.to_bytes(1, 'little') for x in comb)
		allPossibleBlocks.append(byteString)

	perStageCollisions = []
	currentState = initialState

	# The first step is finding collisions at stage 1. Then the shared hash
	# of this collision is used at the next stage, and we find two more colliding
	# blocks. Etc... until we have n collisions to return (see below).
	#
	# perStageCollisions is a list of lists: each list contains two colliding
	# blocks for that stage.
	while (2 ** len(perStageCollisions)) < n:
		nextState, collisions = FindCollisionOneStage(allPossibleBlocks, currentState)

		if not collisions:
			raise Exception("No collision found at current stage.")

		perStageCollisions.append(collisions)
		currentState = nextState

	collisions = []
	# Now we exploit the main principles here: if block X and Y collide at stage 1,
	# and block Z and W collide at stage 2, then each possible concatenation
	# (X+Z, X+W, Y+Z, Y+W) is a collision too. So if the per-stage list has n lists,
	# we are able to produce 2^n collisions.
	#
	# This functions makes the concatenations for us and returns a list with all the 
	# colliding strings.
	GenerateAllCollisions(perStageCollisions, collisions)
	return collisions

def VerifyCollisions(collisions, initialState):
	"""Verifies all the collisions in the input list."""
	sharedH = None

	for c in collisions:
		h = MerkleDamgard(padPKCS7(c), initialState)
		if sharedH is None:
			sharedH = h
		elif sharedH != h:
			return False

	return True

if __name__ == '__main__':
	stateLen = 2

	collisions = FindCollisions(stateLen, 8, b'I\xbf')
	if VerifyCollisions(collisions, b'I\xbf'):
		print('[**] First scenario of challenge 52: found several collisions.')
		print(collisions)
	else:
		print('[**] Nope, not real.')
