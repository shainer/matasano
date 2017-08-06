#!/usr/bin/python3

# Set 3, Challenge 17: the CBC padding oracle.

import base64
from Crypto.Cipher import AES
from Crypto import Random
import random

class PaddingError(Exception):
	pass


def Pkcs7(string):
	"""Applies Pkcs7 padding to a byte string."""
	numPadding = 0

	if len(string) % AES.block_size != 0:
		numPadding = AES.block_size - (len(string) % AES.block_size)

	paddedString = string

	for i in range(0, numPadding):
		paddedString += bytes([numPadding])

	return paddedString

def VerifyPkcs7(string):
	"""Returns True or False depending on whether the byte string 'string'
	has valid Pkcs7 padding applied."""
	paddingFound = False

	# The string was not padded properly, since it is not of the
	# proper size for AES.
	if len(string) % AES.block_size != 0:
		raise Exception('String has not been padded properly.')

	index = len(string) - 1

	lastCh = string[index]
	# The padding bytes cannot be larger than the block size
	# by definition.
	if lastCh > AES.block_size:
		return False

	num_padding = 1
	while True:
		index -= 1
		if string[index] != lastCh:
			break

		num_padding += 1

	return num_padding == lastCh


class CBCPaddingOracle(object):
	def __init__(self):
		self.iv = Random.new().read(AES.block_size)
		self.key = Random.new().read(AES.block_size)
		self.cipher = AES.new(key=self.key, mode=AES.MODE_CBC, IV=self.iv)

		texts = []
		self.plaintexts = []

		# Reads all the lines from the data, as binary strings, then decodes
		# them from base64 and applies Pkcs7 padding.
		with open('data/7.txt', 'rb') as dataFile:
			texts = dataFile.readlines()

		for text in texts:
			strText = base64.b64decode(text)
			self.plaintexts.append(Pkcs7(strText))

	def Encrypt(self):
		# Picks one string at random among the available ones.
		textIndex = random.randint(0, len(self.plaintexts) - 1)
		return self.cipher.encrypt(self.plaintexts[textIndex])

	def VerifyCiphertext(self, ct):
		plaintext = self.cipher.decrypt(ct)
		return VerifyPkcs7(plaintext)


def Block(text, numBlock):
	"""
	Convenience function to return the block with index numBlock in the text.
	Blocks are of AES.block_size size. Indices start from 1, not 0.
	"""
	block = text[(numBlock - 1) * AES.block_size : numBlock * AES.block_size]
	return block

def AttackPadding(blockToBreak, previousBlock):
	"""Decrypts one block of ciphertext using a CBC padding oracle attack,
	knowing the ciphertext block to break and the previous one.

	In the comments below, we refer to the block to break as C2, and the
	previous one as C1.

	Returns the plaintext, or raises PaddingError if decryption was not possible.
	As usual, everything is a byte string.

	A good explanation of the attack can be found at
	http://robertheaton.com/2013/07/29/padding-oracle-attack/
	"""
	brokenPlaintext = b''
	brokenIntermediateState = b''

	modifiedByteIndex = AES.block_size - 1
	chosenPaddingBytes = b''
	validPaddingNumber = 1
	# Number of bytes of c1 we don't care about.
	numRandomBytes = AES.block_size - 1

	for numRandomBytes in range(AES.block_size - 1, -1, -1):
		# Any byte is fine here.
		c1 = b'0' * numRandomBytes

		# We try all possible bytes here. It is possible, that we fail at
		# this stage if nothing produces the valid padding '\x01' that we
		# expect at the first iteration of this attack.
		for byte in range(0, 2 ** 8):
			finalCiphertext = c1 + bytes([byte]) + chosenPaddingBytes + blockToBreak
			if oracle.VerifyCiphertext(finalCiphertext):
				break
		else:
			raise PaddingError('No valid padding could be found')

		# If we get here, we expect the plaintext byte to be validPaddingNumber.
		# It is possible that we are wrong, but it is very unlikely.
		i2 = byte ^ validPaddingNumber
		p2 = previousBlock[modifiedByteIndex] ^ i2

		brokenPlaintext = bytes([p2]) + brokenPlaintext
		brokenIntermediateState = bytes([i2]) + brokenIntermediateState

		validPaddingNumber += 1
		modifiedByteIndex -= 1
		chosenPaddingBytes = b''

		# All the remaining bytes of c1 are now chosen so that the corresponding
		# bytes of P2 must be validPaddingNumber. We use the broken intermediate
		# state to guarantee this.
		for j in range(modifiedByteIndex + 1, 16):
			chosenPaddingBytes += bytes([
				brokenIntermediateState[16 - j - 1] ^ validPaddingNumber])
		chosenPaddingBytes = chosenPaddingBytes[::-1]  # reversed.

	return brokenPlaintext


if __name__ == '__main__':
	oracle = CBCPaddingOracle()

	ciphertext = oracle.Encrypt()
	# Due to padding, this is always an integer number.
	numBlocks = int(len(ciphertext) / AES.block_size)
	brokenPlaintext = b''

	try:
		# We cannot decrypt the first block unless we know the IV. If the IV is
		# some fixed byte string (e.g. all zeroes) then this is possible, otherwise
		# there are too many combinations of a 128-bit strings to be able to brute
		# force it.
		for n in range(numBlocks, 1, -1):
			brokenPlaintext = (AttackPadding(Block(ciphertext, n), Block(ciphertext, n-1))
				+ brokenPlaintext)
		print(brokenPlaintext.decode('ascii'))
	except PaddingError:
		print('Unable to break the ciphertext. Try again!')
