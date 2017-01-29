#!/usr/bin/python3

from Crypto.Cipher import ARC4
from Crypto import Random
import base64
import collections

def RC4Oracle(request):
	cookie = base64.b64decode('QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F')
	#print(cookie)
	plaintext = request + cookie

	key = Random.new().read(16)
	cipher = ARC4.new(key)
	return cipher.encrypt(plaintext)

def IsReadableAscii(byte):
	return byte >= 32 and byte <= 126

if __name__ == '__main__':
	n = 2 ** 24
	biasIndex = 15
	recoveredCookie = ''

	for reqIndex in range(biasIndex):
		request = b'A' * (biasIndex - reqIndex)
		occurrences16 = collections.defaultdict(int)

		for i in range(n):
			if i % (10 ** 6) == 0:
				print('Iteration', i)

			ciphertext = RC4Oracle(request)
			byte16 = ciphertext[biasIndex] ^ 240

			occurrences16[byte16] += 1

		recoveredCookie += max(occurrences16.keys(), key=lambda k: occurrences16[k])
		print('Recovered cookie is:', recoveredCookie)

	print(recoveredCookie)