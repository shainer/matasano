#!/usr/bin/python3

import hashlib
import hmac
import time

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
	realSig = ComputeHMAC(filename)
	print('[**] Real signature is ' + str(realSig))

	recoveredSigPart = b''
	hacked = False

	for sigChar in range(0, 20):
		print('[**] Recovering character ' + str(sigChar))
		if hacked:
			break

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
			if functiming >= (50 * (sigChar + 1)):
				print('Recovered as ' + str(bytes([byte])))
				recoveredSigPart += bytes([byte])
				break

	print(recoveredSigPart)