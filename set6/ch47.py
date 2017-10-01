#!/usr/bin/python3

# Set 6, challenge 47: Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)

from ch42 import BytesToInteger, IntegerToBytes
import math
import rsa
from utils import modexp

KEY_BYTESIZE = 32

class ParityOracle(object):
	def __init__(self, key):
		self._key = key

	def IsValid(self, ciphernum):
		plainnum = rsa.Decrypt(self._key, ciphernum)
		plainbytes = IntegerToBytes(plainnum)

		# Pads the message in front, if necessary. This is because if the number
		# had a leading zero, it would not be translated into bytes.
		while len(plainbytes) < KEY_BYTESIZE:
			plainbytes = b'\x00' + plainbytes

		return plainbytes[0] == 0 and plainbytes[1] == 2

def PKCS1_ENCODE(M):
    # Pad enough to get to the same length in bytes as the public modulo n.
    padding = (KEY_BYTESIZE - len(M) - 3) * b'\xff'
    EM = b'\x00\x02' + padding + b'\x00' + M
    return EM

def PKCS1_DECODE(M):
	if M[0] != 0 or M[1] != 2:
		raise Exception('Cannot decode malformed message')

	# After the first 00 and 02 bytes, there should be a positive number of
	# non-zero bytes (the padding), then 00, then the message.
	for i in range(2, len(M)):
		if M[i] == 0 and i > 2:
			return M[i+1:]

	raise Exception('Cannot decode malformed message')

# This is used for step 1 and for cases where there is more than one interval.
def FindConformingBaseStep(startS, oracle, pubKey, ciphernum):
	e, n = pubKey
	s = startS

	while True:
		c = (ciphernum * pow(s, e, n)) % n
		if oracle.IsValid(c):
			return s
		s += 1

# This is used in case there is exactly one interval, but we have not found
# the solution yet.
def FindConformingFromR(r, oracle, pubKey, ciphernum, interval):
	a, b = interval
	e, n = pubKey
	B = 2 ** (8 * (KEY_BYTESIZE-2))

	# NOTE: for the upper bound of the range, the paper reports
	# (3*B - 1 + r*n) / a. I mistakenly added + 1 at the end to add one
	# to the numerator, since Python ranges do not include the upper bound.
	# However that actually adds 1 to the denominator due to precedence
	# rules. I kept because it makes the whole thing much faster.
	for si in range((2 * B + r * n + b - 1) // b, (3 * B - 1 + r * n) // a + 1):
		c = (ciphernum * pow(si, e, n)) % n
		if oracle.IsValid(c):
			return si

	return None

# Step 3, the computation of new intervals.
def ComputeNextIntervals(Mi, si, n):
	B = 2 ** (8 * (KEY_BYTESIZE-2))
	Mnext = []

	for a, b in Mi:
		for r in range((a*si - 3*B + 1) // n, ((b * si - 2*B) // n) + 1):
			newA = max(a, (2 * B + r * n) // si + 1)
			newB = min(b, (3 * B - 1 + r * n) // si)
			newInterval = (newA, newB)

			if newB >= newA and newInterval not in Mnext:
				Mnext.append(newInterval)

	return Mnext

def Attack(ciphernum, pubKey, oracle):
	e, n = pubKey
	B = 2 ** (8 * (KEY_BYTESIZE-2))

	i = 1
	c0 = ciphernum
	Mi = [(2*B, 3*B - 1)]
	# As suggested in the paper, we skip blinding and set s0 to 1. This is
	# because we are not forging signatures.
	s0 = 1

	s1 = math.ceil(n / (3 * B))
	s1 = FindConformingBaseStep(s1, oracle, pubKey, c0)

	sNext = s1
	while True:
		si = sNext
		sNext = None

		if i == 1:
			s1 = math.ceil(n / (3 * B))
			sNext = FindConformingBaseStep(s1, oracle, pubKey, c0)
		elif len(Mi) == 1:
			a, b = Mi[0]
			if a == b:
				print('Attack successful after %d iterations' % i)
				# This is simpler than the original calculation, but only
				# works because we artificially set s0 to 1 before.
				return a
			else:
				ri = (2 * b * si - 4 * B) // n

				while True:
					sNext = FindConformingFromR(ri, oracle, pubKey, ciphernum, Mi[0])
					if sNext is not None:
						break
					ri += 1
		else:
			sNext = FindConformingBaseStep(s1 + 1, oracle, pubKey, c0)

		Mi = ComputeNextIntervals(Mi, sNext, n)
		i += 1

def GetRSAPair():
	E = 65537
	N = 61042692721884464235697738122307839813042477264962372870792878302623082159791
	D = 9898236043082017813338417428716075097851119224050395969169000482174371385137
	return (E, N), (D, N)

if __name__ == '__main__':
	pubKey, privKey = GetRSAPair()
	oracle = ParityOracle(privKey)

	message = b'kick it, CC'
	print('[**] Encrypting message:', message)
	ciphernum = rsa.Encrypt(pubKey, BytesToInteger(PKCS1_ENCODE(message)))

	plaintextBytes = IntegerToBytes(Attack(ciphernum, pubKey, oracle))
	while len(plaintextBytes) < KEY_BYTESIZE:
		plaintextBytes = b'\x00' + plaintextBytes

	recoveredPlaintext = PKCS1_DECODE(plaintextBytes)
	print('[**] Recovered plaintext:', recoveredPlaintext)
