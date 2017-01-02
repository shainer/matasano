#!/usr/bin/python3

import codecs
import zlib
import string
import base64

from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util import Counter

def padPKCS7(message, k=16):
	if len(message) % k == 0:
		return message

	ch = k - (len(message) % k)
	return message + bytes([ch] * ch)

def FormatRequest(payload):
	"""Formats the request according to the protocol."""

	return (b'POST / HTTP/1.1\n'
		    b'Host: hapless.com\n'
			b'Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=\n'
			b'Content-Length: %d\n%s' % (len(payload), payload))

def Compress(request):
	# NOTE: the compression algorithm obviously matters for the result. Some "leak" less
	# information than others. I have tried LZMA and it only managed to recover the first
	# two characters with the CTR oracle.
	return zlib.compress(request)

def EncryptWithStream(plaintext):
	"""Encrypts using AES in CTR mode with random key and nonce."""
	key = Random.new().read(AES.block_size)
	cipher = AES.new(key=key, mode=AES.MODE_CTR, counter=Counter.new(AES.block_size * 8))
	return cipher.encrypt(plaintext)

def EncryptCBC(plaintext):
	"""Encrypts using AES in CBC mode with random key and IV."""
	key = Random.new().read(AES.block_size)
	iv = Random.new().read(AES.block_size)
	cipher = AES.new(key, AES.MODE_CBC, iv)

	# Note that while we have full control over the request, the compressed
	# version may still need padding for CBC to work.
	return cipher.encrypt(padPKCS7(plaintext))

def OracleCTR(payload):
	"""Compression oracle with stream cipher."""
	req = FormatRequest(payload)
	ct = EncryptWithStream(Compress(req))

	return len(ct)

def OracleCBC(payload):
	"""Compression oracle with CBC."""
	req = FormatRequest(payload)
	ct = EncryptCBC(Compress(req))

	return len(ct)

def GetPadding(payload, oracle):
	paddingAlphabet = b'!@#$%^&*()-`~[]{}'
	l = oracle(payload)
	padding = b''

	# The idea here is to pad with "unique" characters (note that
	# they are not part of the regular alphabet, nor of the rest
	# of the request) until we cross a boundary to the "next"
	# length of the compressed request.
	#
	# This allows for more variation in the length of the
	# compressed request based on optimizations introduced by the
	# algorithm for similarities.
	for i in range(len(paddingAlphabet)):
		padding += bytearray([paddingAlphabet[i]])
		newLen = oracle(padding + payload)

		if newLen > l:
			return padding

	return b''


def BreakWithOracle(sessionIdLength, oracle):
	recoveredId = b''
	# All characters part of the base64 encoding.
	alphabet = str.encode(string.ascii_letters + string.digits + '+/=')

	for i in range(sessionIdLength):
		min_ch = b''
		min_size = 10000

		# These two are only really required for CBC; this is because there
		# is naturally less variation in the ciphertext length when using CBC,
		# because it is always a multiple of the block size.
		#
		# I found out about adding "extra_spaces" by trial and error; prepending
		# it improved things but did not allow me to recover the whole ID.
		extra_spaces = b' ' * 16
		# The ~ character is not important, as long as it does not occur in the
		# rest of the request; this relies on knowing what characters can go in
		# the unknown session ID, or its encoding, but that is not an unreasonable
		# assumption given that we usually deal with public protocols.
		padding = GetPadding((b'sessionid=' + recoveredId + b'~' + extra_spaces) * 8, oracle)

		for ch in alphabet:
			payload = b'sessionid=' + recoveredId + bytearray([ch]) + extra_spaces

			# Repeating the payload multiple time is the key here; if you
			# repeat it only once, there is not enough similar characters
			# for the compression algorithm to use optimizations. Indeed
			# less than 8 repetitions are not enough here; more are enough.
			#print('Calling the oracle with', i, sessionIdLength)
			size = oracle(padding + (payload * 8))

			# At every iteration, we simply pick the character than causes
			# the minimum length in the compressed (and encrypted) request.
			if size < min_size:
				min_size = size
				min_ch = bytearray([ch])

		recoveredId += min_ch

	return recoveredId

if __name__ == '__main__':
	trueSessionId = b'TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE='
	l = len(trueSessionId)

	recoveredIdCTR = BreakWithOracle(l, OracleCTR)
	recoveredIdCBC = BreakWithOracle(l, OracleCBC)

	if recoveredIdCTR == trueSessionId:
		print('[**] (CTR) Session ID recovered successfully:', base64.b64decode(recoveredIdCTR))
	else:
		print('[**] (CTR) Recovered session ID does not match.')

	if recoveredIdCBC == trueSessionId:
		print('[**] (CBC) Session ID recovered successfully:', base64.b64decode(recoveredIdCBC))
	else:
		print('[**] (CBC) Recovered session ID does not match: %s vs. %s'
			  % (recoveredIdCBC, trueSessionId))