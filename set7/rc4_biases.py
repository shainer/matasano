#!/usr/bin/python3

from Crypto.Cipher import ARC4
from Crypto import Random
import base64
import collections

def RC4Oracle(request):
	cookie = base64.b64decode('QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F')
	plaintext = request + cookie

	key = Random.new().read(16)
	cipher = ARC4.new(key)
	return cipher.encrypt(plaintext)

def IsReadableAscii(byte):
	return byte >= 32 and byte <= 126

if __name__ == '__main__':
	# This is a bit more than 16 millions, so recovering each byte
	# takes around 25 minutes. Less means we don't get a clear signal
	# to pick the right byte. The challenge suggested 2 ** 32 but that
	# would be much slower.
	n = 2 ** 24

	# I only wrote the part for the 16th byte; this means that we can
	# only recover the first 16 bytes of the cookie (or less if there
	# is a lower limit on the size of the request we must pass); we
	# can recover the rest by doing the same with biasIndex = 31;
	# the bias this time is toward byte 224.
	biasIndex = 15
	recoveredCookie = ''

	for reqIndex in range(biasIndex):
		# Fill up the request with random data so that the "next"
		# byte of the cookie (from 0 to 16) is aligned with byte 16
		# of the RC4 keystream.
		request = b'A' * (biasIndex - reqIndex)
		# We count the number of occurrences for each byte here. We
		# could skip non-readable bytes but that does not help us
		# much.
		occurrences16 = collections.defaultdict(int)

		for i in range(n):
			if i % (10 ** 6) == 0:
				print('Iteration', i)

			# The idea is that if we bet that byte 16 of the keystream
			# is always equal to the bias, 240 here, then the plaintext
			# byte is the bias XOR the ciphertext byte.
			# This is not true for every case, but it is more likely;
			# enough encryptions of the same plaintext with a different
			# key are going to show a bias toward a specific byte, which
			# we are going to mark as our recovered plaintext byte.
			ciphertext = RC4Oracle(request)
			byte16 = ciphertext[biasIndex] ^ 240

			occurrences16[byte16] += 1

		# Get the key whose value is the maximum in the dictionary,
		# converted to an ASCII character for readability.
		recoveredCookie += chr(max(occurrences16.keys(), key=lambda k: occurrences16[k]))
		print('Recovered cookie is:', recoveredCookie)

	print(recoveredCookie)

