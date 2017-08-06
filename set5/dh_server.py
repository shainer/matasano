#!/usr/bin/python3

import ch33 as dh
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
import random
import socket

# Well, we do not actually verify anything, but we print it. If the MITM
# attack is successful, the server will pass this verification without
# any knowledge that somebody else is reading the messages too.
def VerifySecret(socket, message, secret):
	# Converts the secret to a string and hashes it with SHA1.
	sha1 = hashlib.sha1()
	sha1.update(str(secret).encode())
	privateKey = sha1.hexdigest()

	# Laziness! This should be appended to the ciphertext itself by the client,
	# but I am going to skip that and just pretend we exchanged that already.
	iv = b'\x00' * AES.block_size
	# Taking only 16 digits from a longer hash does not seem like a very secure
	# method, but it's what the challenge recommends for longer hashes.
	cipher = AES.new(key=privateKey[:16], mode=AES.MODE_CBC, IV=iv)
	plaintext = cipher.decrypt(message)
	print(plaintext)


def DHExchangeServer(clientsocket):
	A = 0
	p = 0
	g = 0
	exchange = b''

	# In this scenario, the DH exchange message has this form:
	# BEGIN
	# p
	# g
	# A
	# END
	# (including newlines). Therefore we keep reading 100 bytes
	# until we read D. We do not try and read the whole word
	# because it could fall across a boundary. However this only
	# works because the D is unique (p, g and A are integers).
	while b'D' not in exchange:
		exchange += clientsocket.recv(100)

	exchange = exchange.decode()
	pieces = exchange.split('\n')

	p = int(pieces[1])
	g = int(pieces[2])
	A = int(pieces[3])

	# Computes B and then the secret.
	b = random.randint(0, g - 1)
	B = dh.modexp(g, b, p)
	secret = dh.modexp(A, b, p)

	# Perform our side of the exchange, sending B to the client
	# with the same format.
	messageForClient = 'BEGIN\n%s\nEND' % str(B)
	clientsocket.send(messageForClient.encode())
	return secret


if __name__ == '__main__':
	serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	# Bind the socket locally.
	serversocket.bind(('localhost', 10000))
	serversocket.listen(5)

	# Dumb single-threaded server.
	while True:
		clientsocket, _ = serversocket.accept()
		print('- Accepted new connection.')

		# Perform the DH exchange, server-side, and compute
		# the secret number.
		secret = DHExchangeServer(clientsocket)
		print('The computed secret is', str(secret))

		verificationMessage = clientsocket.recv(48)
		VerifySecret(clientsocket, verificationMessage, secret)
