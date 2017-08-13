#!/usr/bin/python3

import hashlib
import random
import socket
import ch33 as dh

# Dumb utility: we read one byte at a time to avoid reading
# two newlines in the same pass, since we may send pretty
# small numbers.
def ReadUntilNewline(clientsocket):
	data = b''

	while b'\n' not in data:
		data += clientsocket.recv(1)

	return data[:-1]

def SRPSetup(clientsocket):
	g = 2
	k = 3
	# Use the same large prime we used before.
	N = int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e340'
		    '4ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f40'
		    '6b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8f'
		    'd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff', 16)
	# Server and client have agreed already on a password.
	P = b'mybeautifulpassword'

	# Random salt.
	salt = random.randint(1, 100000)
	saltBytes = str(salt).encode()

	# Hash salt|password and convert the result to an integer, x. We do
	# this by simply taking the decimal equivalent of the hash.
	sha = hashlib.sha256()
	sha.update(saltBytes)
	sha.update(P)
	xhash = sha.hexdigest()

	x = int(xhash, 16)
	v = dh.modexp(g, x, N)

	# We don't actually make any use of the email in this exercise,
	# but in a real implementation we would associate the email with
	# the expected password, and/or do other verifications.
	email = ReadUntilNewline(clientsocket)
	A = ReadUntilNewline(clientsocket)

	b = random.randint(1, 10000)
	B = k*v + dh.modexp(g, b, N)

	clientsocket.send(saltBytes + b'\n')
	clientsocket.send(str(B).encode() + b'\n')

	sha = hashlib.sha256()
	sha.update(A)
	sha.update(str(B).encode())
	u = int(sha.hexdigest(), 16)

	S = dh.modexp((int(A) * dh.modexp(v, u, N)), b, N)

	sha = hashlib.sha256()
	sha.update(str(S).encode())
	K = sha.hexdigest()

	# Returns both K and saltBytes as byte strings. This helps later
	# since we hash them.
	return K.encode(), saltBytes

if __name__ == '__main__':
	serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	# Bind the socket locally.
	serversocket.bind(('localhost', 10000))
	serversocket.listen(5)

	# Dumb single-threaded server.
	while True:
		clientsocket, _ = serversocket.accept()
		print('- Accepted new connection.')

		K, salt = SRPSetup(clientsocket)

		sha = hashlib.sha256()
		sha.update(salt)
		sha.update(K)

		digest = sha.hexdigest().encode()
		password = clientsocket.recv(64)

		# Compare our digest with the one produced by the client.
		if password == digest:
			clientsocket.send(b'OK')
		else:
			clientsocket.send(b'NO')

		clientsocket.close()
