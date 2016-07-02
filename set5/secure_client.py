#!/usr/bin/python3

import diffie_hellman as dh
import hashlib
import random
import socket
import sys

def ReadUntilNewline(clientsocket):
	data = b''

	while b'\n' not in data:
		data += clientsocket.recv(1)

	return data[:-1]

# If isClientGood == True, we do SRP for real (Challenge 36).
# Otherwise, we break the exchange as per Challenge 37.
def SRPSetup(sock, email, password, isClientGood):
	g = 2
	k = 3
	N = int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e340'
		    '4ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f40'
		    '6b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8f'
		    'd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff', 16)

	sock.send(email.encode() + b'\n')

	a = random.randint(0, 10000)

	if isClientGood:
		A = dh.modexp(g, a, N)
	else:
		# Sending this means that S = 0 server-side, since
		# A is the base of the modexp computing S, so all the
		# other parameters get ignored.
		# The other tweaking proposed, A = N or A = kN, have the
		# exact same effect, since you compute S = (A ** x) % A
		# which is equal to 0 no matter what 'x' is.
		A = 0

	message = (str(A) + '\n').encode()
	sock.send(message)

	salt = ReadUntilNewline(sock)
	B = ReadUntilNewline(sock)

	sha = hashlib.sha256()
	sha.update(str(A).encode())
	sha.update(B)
	u = int(sha.hexdigest(), 16)

	sha = hashlib.sha256()
	sha.update(salt)
	sha.update(password.encode())
	x = int(sha.hexdigest(), 16)

	if isClientGood:
		exp = (a + u * x)
		base = (int(B) - k * dh.modexp(g, x, N))
		S = dh.modexp(base, exp, N)
	else:
		# If we have been bad, we know the server has computed S = 0,
		# so we do the same on our side. We could also avoid computing
		# a bunch of other parameters before (namely, x and u).
		# At this point the secret is independent of which password
		# we send to the server, so we can send an empty one and still
		# be accepted as good users.
		S = 0

	sha = hashlib.sha256()
	sha.update(str(S).encode())
	K = sha.hexdigest()

	return K, salt

if __name__ == '__main__':
	isGoodMode = True

	if len(sys.argv) > 1:
		if sys.argv[1] == 'good':
			isGoodMode = True
		elif sys.argv[1] == 'bad':
			isGoodMode = False

	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect(('localhost', 10000))

	email = input('[**] Enter email address: ')
	password = input('[**] Enter password: ')
	K, salt = SRPSetup(sock, email, password, isGoodMode)

	sha = hashlib.sha256()
	sha.update(salt)
	sha.update(K.encode())
	digest = sha.hexdigest()

	sock.send(digest.encode())
	reply = sock.recv(2)

	if reply == b'OK':
		print('[**] Password accepted. You have full control of the nuclear reactor!')
	elif reply == b'NO':
		print('[!!] Incorrect password.')
	else:
		print('Unrecognized reply by the server:', reply)

	sock.close()