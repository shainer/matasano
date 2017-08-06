#!/usr/bin/python3

import ch33 as dh
import hashlib
from Crypto.Cipher import AES
import random
import socket

# Set 5, challenge 34: Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection.

def DHExchangeBadServer(clientsocket, mysocket):
	A = 0
	p = 0
	g = 0
	exchange = b''

	while b'D' not in exchange:
		exchange += clientsocket.recv(100)

	exchange = exchange.decode()
	pieces = exchange.split('\n')

	# We do not care about A, but we need p and g.
	p = int(pieces[1])
	g = int(pieces[2])

	# Relay a message to the good server by replacing A with p.
	# This means that B will be modexp(p, b, p), which, no matter
	# what the value of b is, is equal to 0.
	relayedMessage = 'BEGIN\n%s\n%s\n%s\nEND' % (str(p), str(g), str(p))
	mysocket.send(relayedMessage.encode())

	# For the same reason, relay a message to the client where B
	# is replaced by p. Now A will be equal to 0 too.
	messageForClient = 'BEGIN\n%s\nEND' % str(p)
	clientsocket.send(messageForClient.encode())
	return 0

# This is the same as for the 'good' server, since we correctly
# guessed the secret key.
def VerifySecret(clientsocket, message, secret):
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

if __name__ == '__main__':
	serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	# Bind the socket locally.
	serversocket.bind(('localhost', 10002))
	serversocket.listen(5)

	# Dumb single-threaded server.
	while True:
		clientsocket, _ = serversocket.accept()
		print('- Accepted new connection.')

		# We open a new connection for the 'good' server every time
		# to simulate the client behaviour.
		mysocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		mysocket.connect(('localhost', 10000))

		# If you read the function you find out the secret can be
		# predicted without computation :)
		secret = DHExchangeBadServer(clientsocket, mysocket)
		print('The computed secret is', str(secret))

		# Gets the verification message, decrypts it, and then
		# relays it to the server so nothing is suspected.
		verificationMessage = clientsocket.recv(48)
		VerifySecret(clientsocket, verificationMessage, secret)
		mysocket.send(verificationMessage)

		mysocket.close()
