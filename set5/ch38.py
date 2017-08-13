#!/usr/bin/python3

import hashlib
import random
import socket
import ch33 as dh

# Set 5, challenge 38: Offline dictionary attack on simplified SRP. Attacker server.
# This replaces the proper server at simplified_srp_server and sends broken
# parameters in order to be able to recover the full password from the
# client's messages.

SERVER_PORT = 10001

# Dumb utility: we read one byte at a time to avoid reading
# two newlines in the same pass, since we  send pretty small messages.
def ReadUntilNewline(clientsocket):
	data = b''

	while b'\n' not in data:
		data += clientsocket.recv(1)

	return data[:-1]

def SRPDictionaryAttack(clientsocket):
	# The server needs to know at least g and N, basic parameters of the protocol,
	# for this to work, since they are both used several times below.
	g = 2
	#k = 3
	N = int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e340'
			'4ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f40'
			'6b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8f'
			'd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff', 16)

	# Random salt.
	salt = str(random.randint(1, 100000)).encode()

	# Do all the communication with the client upfront (minus the final "yes or
	# no" from the server) so we have the client's digest to compare with our
	# own.
	# Note that this is only possible because the computation of B does not
	# depend on the password digest itself.
	email = ReadUntilNewline(clientsocket)
	A = ReadUntilNewline(clientsocket)

	b = random.randint(1, 10000)
	# The challenge mentions to have an arbitrary value for B, but it has
	# to be this one or the S differs between client and server, and therefore
	# the password digests never match.
	# Anyway B depends on b which is random, and g and N which are protocol
	# parameters.
	B = dh.modexp(g, b, N)

	clientsocket.send(salt + b'\n')
	clientsocket.send(str(B).encode() + b'\n')

	u = random.getrandbits(128)
	clientsocket.send(str(u).encode() + b'\n')

	clientDigest = clientsocket.recv(64)

	# Most systems have /usr/share/dict/words, but here that contains bytes,
	# while this has the usual "one string per line" format.
	with open('/usr/share/dict/cracklib-small', 'r') as w:
		# For each password, compute the final digest and compare with the
		# digest received by the client. If we find a match we cracked the
		# password, otherwise the client was smart enough not to pick a
		# password that can be broken with a dictionary attack.
		for p in w.readlines():
			password = p.strip().encode()

			sha = hashlib.sha256()
			sha.update(salt)
			sha.update(password)
			xhash = sha.hexdigest()

			x = int(xhash, 16)
			v = dh.modexp(g, x, N)

			S = dh.modexp((int(A) * dh.modexp(v, u, N)), b, N)
			sha = hashlib.sha256()
			sha.update(str(S).encode())
			K = sha.hexdigest().encode()

			sha = hashlib.sha256()
			sha.update(salt)
			sha.update(K)
			digest = sha.hexdigest().encode()

			if clientDigest == digest:
				print('Cracked password:', p.strip())
				break
		else:
			print('Unable to crack password, sorry.')


if __name__ == '__main__':
	serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	# Bind the socket locally.
	serversocket.bind(('localhost', SERVER_PORT))
	serversocket.listen(5)

	# Dumb single-threaded server.
	while True:
		clientsocket, _ = serversocket.accept()
		print('- Accepted new connection.')

		SRPDictionaryAttack(clientsocket)
		# Send NO no matter what :-)
		clientsocket.send(b'NO')
		clientsocket.close()
