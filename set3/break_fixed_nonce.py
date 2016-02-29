#!/usr/bin/python3

from Crypto.Cipher import AES
from Crypto import Random
import ctr_decryption
import base64
from plaintext_verifier import PlaintextVerifier

def EncryptWithFixedNonce(plaintextes):
	"""Challenge setup: encrypt all the plaintextes separately with
	a fixed nonce (0) and fixed random key."""
	result = []
	key = Random.new().read(AES.block_size)

	for pt in plaintextes:
		ct = ctr_decryption.DoCTR(
			base64.b64decode(pt), key, 0)
		result.append(ct)

	return result

def IsReadable(byte):
	"""Returns True if the character is in readable ASCII range."""
	return byte in list(range(32, 127)) + [10]

def RecoverByteAllUpper(ciphertextes):
	"""Return the keystream byte such that the first char
	of all ciphertextes decrypt to an upper case letter."""
	resByte = -1

	for keyByte in range(0, 256):
		for ct in ciphertextes:
			ptByte = ct[0] ^ keyByte

			# Found a counterexample ciphertext, we can stop.
			if not IsReadable(ptByte) or chr(ptByte) < 'A' or chr(ptByte) > 'Z':
				break
		else:
			# Found the valid byte.
			resByte = keyByte
			break

	if resByte == -1:
		raise Exception('No byte found')

	return resByte

def UpdatePlaintextes(cts, charIndex, pts, keyByte):
	"""Utility function to update all the plaintextes knowing the next byte
	of the keystream that was used to encrypt them."""
	index = 0

	for pt in pts:
		# Some strings are shorter than others, so this could
		# be out of range. Just skip them.
		if charIndex >= len(cts[index]):
			index += 1
			continue

		# Decrypt. The result should be readable or keyByte is
		# not valid and we need to try a different guess.
		pts[index] += chr(cts[index][charIndex] ^ keyByte)
		index += 1

	return pts

def RecoverByteEqual(cts, index, charIndex, expectedChar):
	"""Return keyByte such that the character at position charIndex of
	the ciphertext with index 'index' decrypts to expectedChar."""

	for keyByte in range(0, 256):
		ptByte = cts[index][charIndex] ^ keyByte
		if IsReadable(ptByte) and chr(ptByte) == expectedChar:
			return keyByte

	raise Exception('No byte found')

# The method used here is not orthodox, as the challenge itself suggested.
# There are too many possibilities for an efficient backtracking algorithm,
# even eliminating all non-readable bytes from the possible plaintextes;
# moreover, most heuristics to recognize English plaintext need a few characters
# to work with, reducing early pruning.
#
# This is the approach: I used with the assumption that all textes must
# start with a capital letter, which was correct (other assumptions failed :-)).
# Then at each iteration of the for-loop below, I basically look at all the
# partially recovered plaintextes and try to guess the likely next character
# for one text; I then recover the key byte that would have generated that
# character for that text and apply it to all textes. I print the result, if
# it is sensible, I repeat with the next character, and so on.
# This was very easy: several first characters were 'W', which led me to
# guess 'h'; then two other strings were 'Or', so I guessed a whitespace next,
# and so on. Guessing whitespaces was especially a good idea since at least one
# string was bound to be at the end of a word in most iterations. After a while
# I just googled the first partial text and found the whole poem to recover
# the last characters.
#
# Since not all textes are of the same length, at the end I just 'guess' the
# remaining characters for the longest ones; the shortest ones are ignored.
#
# The guessed characters were collected in guessedNextChars, while the indices
# of the strings for which they were guessed are in guessedStringIndex.
def RecoverPlaintext(ciphertextes):
	recoveredKeystream = b''
	plaintextes = [''] * len(ciphertextes)

	keyByte = RecoverByteAllUpper(ciphertextes)
	plaintextes = UpdatePlaintextes(ciphertextes, 0, plaintextes, keyByte)

	maxTextLength = len(max(ciphertextes, key=len))
	guessedNextChars = 'h  ng tle  d mury ss e ng y ay headn'
	guessedStringIndex = [20, 5, 8, 1, 1, 1, 27, 39, 39, 39, 1, 4, 4, 0, 3, 3,
						  3, 3, 5, 5, 5, 6, 6, 39, 2, 2, 14, 37, 0, 0, 4, 4,
						  4, 4, 4, 37]

	for nextTextIndex in range(1, len(guessedNextChars) + 1):
		keyByte = RecoverByteEqual(
			ciphertextes, guessedStringIndex[nextTextIndex - 1], nextTextIndex,
			guessedNextChars[nextTextIndex - 1])

		plaintextes = UpdatePlaintextes(ciphertextes, nextTextIndex, plaintextes, keyByte)

	for pt in plaintextes:
		print(pt)

if __name__ == '__main__':
	plaintextes = []

	# Read the input.
	with open('data/19.txt', 'rb') as data:
		plaintextes = data.readlines()

	ciphertextes = EncryptWithFixedNonce(plaintextes)
	RecoverPlaintext(ciphertextes)