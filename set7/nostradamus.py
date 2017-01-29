#!/usr/bin/python3

from Crypto.Cipher import AES
from Crypto import Random
import collections
import itertools
import math

def padPKCS7(message, k=AES.block_size):
	"""Usual PKCS#7 padding."""
	if len(message) % k == 0:
		return message

	ch = k - (len(message) % k)
	return message + bytes([0] * ch)

def GetNumBlocks(message):
	return math.ceil(len(message) / AES.block_size)

def GetBlock(message, index):
	# To make it easier, I assume there are always perfectly-sized blocks
	# in the input.
	return message[index * AES.block_size:(index+1) * AES.block_size]

def MerkleDamgard(message, state, stateLen):
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

# Generates the initial 2**k states of the tree at random. We make
# all of them different with each other.
def RandomUniqueStates(n, stateLen):
	states = []

	while len(states) < n:
		state = Random.new().read(stateLen)

		if state not in states:
			states.append(state)

	return [(b'', b'', x) for x in states]

def FindCollisions(previousStates, allPossibleBlocks, stateLen):
	newStates = []

	# Given the two states s1 and s2, we want to find two blocks, b1
	# and b2, such that H(b1, s1) = H(b2, s2). This would work even
	# with one block, but finding collisions that way is very hard
	# and we would have had to look hard for suitable trees.
	for i in range(0, len(previousStates) - 1, 2):
		s1 = previousStates[i][2]
		s2 = previousStates[i+1][2]
		hashes = {}

		for block in allPossibleBlocks:
			h1 = MerkleDamgard(padPKCS7(block), s1, stateLen)
			h2 = MerkleDamgard(padPKCS7(block), s2, stateLen)

			if h1 in hashes:
				newStates.append((block, hashes[h1], h1))
				break

			hashes[h2] = block
		else:
			raise Exception('Collision not found between %s and %s' % (s1, s2))

	return newStates


# The collision tree is structured as a dictionary from level number (0 = leaves)
# to list of tuples. Each tuple contains the two colliding blocks and the state
# they collide to from the previous level. The leaves have two empty blocks
# associated instead.
def GenerateCollisionTree(k, stateLen):
	nodesByLevel = collections.defaultdict(list)

	allBytes = range(2 ** 8)
	allPossibleBlocks = []
	for comb in itertools.combinations(allBytes, stateLen):
		byteString = b''.join(x.to_bytes(1, 'little') for x in comb)
		allPossibleBlocks.append(byteString)

	for level in range(k+1):
		nodes = []

		if level == 0:
			nodes = RandomUniqueStates(2 ** k, stateLen)
		else:
			nodes = FindCollisions(nodesByLevel[level-1], allPossibleBlocks, stateLen)
		print('Generated nodes for level %d: %s' % (level, str(nodes)))
		nodesByLevel[level] = nodes

	return nodesByLevel

# Now I generate a meaningful message, crafted so that it's exactly 1 block
# length, but there is no need to do so. Nobody should be seeing this
# message, only the hash.
def GeneratePrediction(k, messageLen, state, stateLen):
	fakeMessage = b'Thanks audience!'
	return MerkleDamgard(fakeMessage, state, stateLen)

def ForgeHash(forgedPrediction, stateLen, collisionTree, k):
	allBytes = range(2 ** 8)
	allPossibleBlocks = []
	for comb in itertools.combinations(allBytes, stateLen):
		byteString = b''.join(x.to_bytes(1, 'little') for x in comb)
		allPossibleBlocks.append(byteString)

	leaves = [x[2] for x in collisionTree[0]]
	firstPartHash = MerkleDamgard(forgedPrediction, b'\x00\x00', stateLen)

	block = b''
	leaf = b''
	leafIndex = -1

	# Find the leaf we collide into, and store both the leaf tuple and its
	# index inside the list.
	for block in allPossibleBlocks:
		h = MerkleDamgard(padPKCS7(block), firstPartHash, stateLen)
		if h in leaves:
			leaf = h
			leafIndex = leaves.index(h)
			break
	else:
		raise Exception('No collision leaf found')	

	# Add the "glue" block to the forgery.
	forgedPrediction += padPKCS7(block)
	suffix = b''

	# Now we follow the tree from the leaf we found at the previous stage
	# to the root. Every time we pick the suitable block of the two choices
	# depending on which node we landed into (see pieceIndex).
	for i in range(1, k+1):
		level = collisionTree[i]

		pieceIndex = -1
		if leafIndex % 2 == 0:
			pieceIndex = 0
		else:
			pieceIndex = 1

		leafIndex = math.floor(leafIndex / 2)
		piece = padPKCS7(level[leafIndex][pieceIndex])

		suffix += piece

	# We need to add the original message (or better, its first block)
	# or the hash of the forgery is simply going to be the root of the
	# collision tree.
	# 
	# Alternatively, I suppose you could hash the initial prediction with
	# one of the states at the first level of the tree, just before the root,
	# and then both the prediction and the forgery would have collided into
	# the root.
	suffix += b'Thanks audience!'
	# I am not convinced this makes a compelling case; sure we can write
	# whatever we want in the initial blocks of the prediction, but then
	# we are forced to append a bunch of unreadable blocks to make this
	# work. It looks pretty obvious to me :D
	forgedPrediction += suffix
	print('Complete forgery:', forgedPrediction)
	return MerkleDamgard(forgedPrediction, b'\x00\x00', stateLen)

if __name__ == '__main__':
	k = 5
	stateLen = 2
	messageLen = 100

	collisionTree = GenerateCollisionTree(k, stateLen)
	hashedPrediction = GeneratePrediction(k, messageLen, collisionTree[k][0][2], stateLen)
	print('The hashed prediction is', hashedPrediction)

	forgedPrediction = b'Something sport related. Yay!!!!'
	forgedPredictionHash = ForgeHash(forgedPrediction, stateLen, collisionTree, k)

	if forgedPredictionHash == hashedPrediction:
		print('[**] Our prediction passed the test')
		print('%s with hash %s' % (forgedPrediction, forgedPredictionHash))
	else:
		print('Failed: got %s expected %s' % (forgedPredictionHash, hashedPrediction))