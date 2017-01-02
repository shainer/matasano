#!/usr/bin/python3

import codecs
import zlib
import string
import base64

from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util import Counter

def FormatRequest(payload):
	"""Formats the request according to the protocol."""

	return (b'POST / HTTP/1.1\n'
		    b'Host: hapless.com\n'
			b'Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=\n'
			b'Content-Length: %d\n%s' % (len(payload), payload))

def Compress(request):
	# NOTE: the compression algorithm obviously matters for the result. Some "leak" less
	# information than others. I have tried LZMA and it only managed to recover the first
	# two characters.
	return zlib.compress(request)

def EncryptWithStream(plaintext):
	"""Encrypts using AES in CTR mode with random key and nonce."""
	key = Random.new().read(AES.block_size)
	cipher = AES.new(key=key, mode=AES.MODE_CTR, counter=Counter.new(AES.block_size * 8))
	return cipher.encrypt(plaintext)

def OracleCTR(payload):
	"""Compression oracle."""
	req = FormatRequest(payload)
	ct = EncryptWithStream(Compress(req))

	return len(ct)

if __name__ == '__main__':
	trueSessionId = b'TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE='
	l = len(trueSessionId)

	recoveredId = b''
	# All characters part of the base64 encoding.
	alphabet = str.encode(string.ascii_letters + string.digits + '+/=')

	for i in range(l):
		min_ch = b''
		min_size = 10000

		for ch in alphabet:
			payload = b'sessionid=' + recoveredId + bytearray([ch])
			# Repeating the payload multiple time is the key here; if you
			# repeat it only once, there is not enough similar characters
			# for the compression algorithm to use optimizations. Indeed
			# less than 8 repetitions are not enough here; more are enough.
			size = OracleCTR(payload * 8)

			# At every iteration, we simply pick the character than causes
			# the minimum length in the compressed (and encrypted) request.
			if size < min_size:
				min_size = size
				min_ch = bytearray([ch])

		recoveredId += min_ch

	if recoveredId == trueSessionId:
		print('[**] Session ID recovered successfully:', base64.b64decode(recoveredId))
	else:
		print('[**] Recovered session ID does not match.')