#!/usr/bin/python3

import hashlib
import hmac
import time

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
		time.sleep(0.05)

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

		# We try each possible byte; we stop when we find the byte
		# for which the verification signature takes more than 50 ms times
		# how many correct bytes we have before this one.
		#
		# It is also possible that we get subsequent bytes correct by
		# accident. This means we are cracking the byte of index 0, but
		# byte of index 1 is '\x00' so that is correct too. If this happens
		# we still get a running time greater than 50 ms times the correct
		# bytes we know about, so it works. It is not very efficient though
		# as we will repeat the same cracking procedure for byte 1 despite
		# already discovering its value; we can consider the situation unlikely
		# enough to not have a great impact on performance in the average case.
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

			functiming = (end_time - start_time) * 1000
			# This requires us "knowing" or "discovering" the 50ms timing leak, which
			# stands out quite a bit if you look at all the timings for each possible
			# byte value.
			# Another option is to keep the value which generates the maximum running
			# time. Both methods should break at the next challenge
			if functiming >= (50 * (sigChar + 1)):
				print('Recovered as ' + str(bytes([byte])))
				recoveredSigPart += bytes([byte])
				break

	print(recoveredSigPart)