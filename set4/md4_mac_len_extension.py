#!/usr/bin/python3

from md4_mac import MD4Sign
from md4_mac import MD4
from md4_mac import _pad
import binascii
import struct

def makeGluePadding(message, keylen):
	byteLength = len(message) + keylen
	bitLength = byteLength * 8
	index = (bitLength >> 3) & 0x3f

	padLength = 120 - index
	if index < 56:
		padLength = 56 - index
	
	padding = b'\x80' + b'\x00'*63
	return padding[:padLength] + struct.pack('<Q', bitLength)

def RecoverInternalState(secretHash):
	t = struct.unpack('<IIII', binascii.unhexlify(secretHash))
	return [t[0], t[1], t[2], t[3]]

def GetRealDigest(message):
	md4 = MD4()
	md4.update(b'YELLOW SUBMARINE')
	md4.update(message)
	return md4.digest()

# FIXME: does not work yet, despite the glue and recovered
# state being verified.
if __name__ == '__main__':
	message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
	secretHash = MD4Sign(message)

	# FIXME: discover the key length normally, this is cheating :)
	keyLen = 16
	forgedPart = b';admin=true'

	# The new message length is the length of the key + the
	# original message + the artificial padding glue + the
	# part we added ourselves.
	glue = makeGluePadding(message, keyLen)
	# After the forged part, the MD4 algorithm may add more
	# padding, but that happens internally so we do not need
	# to factor its length here.
	fakeLen = keyLen + len(message) + len(glue) + len(forgedPart)

	# Create a MD4 object with our own H vector. This allows us
	# to extend the hash from where we started.
	h = RecoverInternalState(secretHash)
	print("Forged state is " + str(h))
	md4 = MD4(h)
	md4.update(forgedPart, fakeLen)
	digest = md4.digest()
	realThing = GetRealDigest(message + glue + forgedPart)

	if digest == realThing:
		print('[**] We did it')
		print(digest)
		print('Key length was', keyLen)
	else:
		print("Nope")
		print(digest)
		print(realThing)