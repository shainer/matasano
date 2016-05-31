#!/usr/bin/python3

from sha1_mac import Sha1Sign
from sha1_mac import Sha1Hash
import hashlib
import struct

def makeGluePadding(message, keylen):
	byteLength = len(message) + keylen
	padding = b''

	# Appends the bit '1' to the message.
	padding += b'\x80'
	# Appends the byte '0' k times; k is such that the resulting
	# message length in bits is congruent to 64.
	padding += b'\x00' * ((56 - (byteLength + 1) % 64) % 64)
	# Appends the message length in bits as a 64-bit big-endian
	# integer (Q is unsigned long long for the struct module).
	padding += struct.pack(b'>Q', byteLength * 8)
	return padding

def RecoverInternalState(secretDecimalHash):
	a = secretDecimalHash >> 128
	b = (secretDecimalHash >> 96) & 0xffffffff
	c = (secretDecimalHash >> 64) & 0xffffffff
	d = (secretDecimalHash >> 32) & 0xffffffff
	e = secretDecimalHash & 0xffffffff
	return [a, b, c, d, e]

def GetRealDigest(message):
	sha = hashlib.sha1()
	sha.update(b'YELLOW SUBMARINE')
	sha.update(message)
	return sha.hexdigest()

# FIXME: here we assume to know the exact length of the secret key
# used to produce the MAC. We need our algorithm to discover the
# length itself.
if __name__ == '__main__':
	message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
	secretHash = Sha1Sign(message)

	# Even if we try all possibilities up to 10.000, the loop only
	# takes a few seconds, so brute force works here. Secret keys are
	# also generally smaller than 10.000 bytes.
	for keyLen in range(1, 10000):
		decimalHash = int(secretHash, 16)
		forgedPart = b';admin=true'

		# The new message length is the length of the key + the
		# original message + the artificial padding glue + the
		# part we added ourselves.
		glue = makeGluePadding(message, keyLen)
		# After the forged part, the SHA1 algorithm may add more
		# padding, but that happens internally so we do not need
		# to factor its length here.
		fakeLen = keyLen + len(message) + len(glue) + len(forgedPart)

		# Create a SHA1 object with our own H vector. This allows us
		# to extend the hash from where we started.
		h = RecoverInternalState(decimalHash)
		sha1 = Sha1Hash(h)
		digest = sha1.digest(b';admin=true', fakeLen)
		realThing = GetRealDigest(message + glue + forgedPart)

		if digest == realThing:
			print('[**] We did it')
			print(digest)
			print('Key length was', keyLen)
			break
	else:
		print('Nothing found for key lengths up to 10000 bytes')