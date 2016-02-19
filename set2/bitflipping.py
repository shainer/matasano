#!/usr/bin/python3

import aes_lib
from Crypto.Cipher import AES

def _Padding(string, blockSize):
	"""Returns the amount of padding bytes we need to add."""
	if len(string) % blockSize == 0:
		return 0

	return blockSize - (len(string) % blockSize)

def StripPkcs7(string, blockSize):
	paddingFound = False

	if len(string) % blockSize != 0:
		raise Exception('String has not been padded properly.')

	index = len(string) - 1

	lastCh = string[index]
	if lastCh > blockSize:
		return string

	num_padding = 1
	while True:
		index -= 1
		if string[index] != lastCh:
			break

		num_padding += 1

	if num_padding != lastCh:
		raise Exception('Wrong padding applied.')

	return string[:index+1]

def Pkcs7(string, blockSize):
	numPadding = _Padding(string, blockSize)
	paddedString = string

	for i in range(0, numPadding):
		paddedString += bytes(bytearray([numPadding]))

	return paddedString

def BitflippingEncryption(aes, inputBytes):
	"""Encloses the input byte string in a cookie, and encrypts
	with AES in CBC mode."""

	# Avoids injection of admin=true by disallowing the '=' character.
	if ord('=') in inputBytes:
		raise Exception('Invalid characters in input text')

	plaintext = b'comment1=cooking%20MCs;userdata='
	plaintext += inputBytes
	plaintext += b';comment2=%20like%20a%20pound%20of%20bacon'
	plaintext = Pkcs7(plaintext, 16)  # padding

	return aes.SimulateCBCEncryption(plaintext)

def BitflippingDecryption(aes, ciphertext):
	plaintext = aes.SimulateCBCDecryption(ciphertext)
	return StripPkcs7(plaintext, 16)

def BitflippingDecryptAndVerify(aes, ciphertext):
	pt = BitflippingDecryption(aes, ciphertext)
	return (b'admin=true' in pt)

if __name__ == "__main__":
	aes = aes_lib.AESCipher(mode=AES.MODE_ECB)

	# The idea behind this attack: my userdata cannot contain '='
	# so I cannot simply inject an admin=true in it. I insert a
	# 'adminXtrue' (where 'X' is any other allowed character), then
	# exploit CBC to replace 'X' with '='.

	# It does not really matter what it goes in the userdata beside
	# adminXtrue, as long as you keep track of the length of the
	# text you add before it.
	pt = b'I am the queen of crypto'  # len here is 24
	pt += b'adminXtrue'
	pt += b'Witness my power!'

	ct = BitflippingEncryption(aes, pt)

	# This is the index of the ciphertext byte that is in the previous
	# block of my X above, at the same offset from the beginning of
	# the block. So if my X is the third byte in its block, this will
	# be the index of the third byte of the previous block. The cookie
	# already guarantees me to have blocks before my userdata, otherwise
	# you could just use the data before adminXtrue.
	offset = len('comment1=cooking%20MCs;userdata=') + 24 + 5 - 16

	# To see why this correction works, a good explanation can be found
	# at http://resources.infosecinstitute.com/cbc-byte-flipping-attack-101-approach/
	flipped = ct[offset] ^ ord('X') ^ ord('=')

	# Replaces only that byte in the ciphertext.
	flippedCipherText = ct[:offset]
	flippedCipherText += bytes([flipped])
	flippedCipherText += ct[offset+1:]

	is_admin = BitflippingDecryptAndVerify(aes, flippedCipherText)

	if is_admin:
		print('Admin found in cookie.')
	else:
		print('Admin not found in cookie.')
