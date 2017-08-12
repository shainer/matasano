#!/usr/bin/python3

import hashlib
import hmac
import time

# Set 4, challenge 32: break HMAC-SHA1 with a slightly less artificial timing leak.

# Compute the HMAC of the file content.
def ComputeHMAC(filename):
	bindata = None

	with open(filename, 'rb') as binfile:
		bindata = binfile.read()

	h = hmac.new(key=b'YELLOW SUBMARINE', digestmod=hashlib.sha1)
	h.update(bindata)
	return h.digest()

def InsecureCompare(sig1, sig2):
	for b in range(len(sig1)):
		if sig1[b] != sig2[b]:
			return False
		time.sleep(0.005)

	return True

def verifySignature(filename, signature):
	realSig = ComputeHMAC(filename)
	return InsecureCompare(realSig, signature)


if __name__ == '__main__':
	filename = 'data/25.txt'

	# "Cheating" to verify we cracked it right.
	realSig = ComputeHMAC(filename)
	print('[**] Real signature is ' + str(realSig))

	recoveredSigPart = b''
	hacked = False

	for sigChar in range(0, 20):
		print('[**] Recovering character ' + str(sigChar))
		if hacked:
			break

		maxTiming = 0
		maxByte = -1

		for byte in range(0, 256):
			missingPartLen = 20 - sigChar - 1
			signature = recoveredSigPart + bytes([ byte ]) + b'\x00' * missingPartLen

			start_time = time.time()
			matches = verifySignature(filename, signature)
			end_time = time.time()

			if matches:
				print('Signature hacked: ' + str(signature))
				hacked = True
				break

			# Very easy: we try each byte and take the one for which the comparison
			# time was longer. There's probably a threshold at which that does
			# not guarantee results. At that point I would probably take the
			# 2-3 bytes with the longest timing and try all the possible
			# combinations? If we are recovering something in English it would
			# be sensible to apply heuristics, but signatures don't fall in that
			# category.
			functiming = (end_time - start_time) * 1000
			if functiming > maxTiming:
				maxTiming = functiming
				maxByte = byte

		print('Recovered as ' + str(bytes([maxByte])))
		recoveredSigPart += bytes([maxByte])

	print(recoveredSigPart)
