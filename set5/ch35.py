#!/usr/bin/python3

import ch33 as dh
import hashlib
from Crypto.Cipher import AES
import random
import socket

# Set 4, challenge 35: Implement DH with negotiated groups, and break with malicious "g" parameters.

# This contains all the three attacks for Challenge 35.
# I should have a command line parameter for deciding
# which one to apply.

# Common code factored out.
def ReadOtherParameters(clientsocket):
	A = 0
	p = 0
	exchange = b''

	while b'D' not in exchange:
		exchange += clientsocket.recv(100)

	exchange = exchange.decode()
	pieces = exchange.split('\n')

	p = int(pieces[1])
	A = int(pieces[3])
	return A, p

# 1st attack: set g = 1.
# The server computes B = 1^b mod p = 1 no matter the rest of the parameters,
# and we pass B = 1 to the client. A stays correct.
# At both sides, the final secret is 1.
def DHExchangeBadServer1(clientsocket, mysocket):
	A, p = ReadOtherParameters(clientsocket)
	my_g = 1

	relayedMessage = 'BEGIN\n%s\n%s\n%s\nEND' % (str(p), str(my_g), str(A))
	mysocket.send(relayedMessage.encode())

	messageForClient = 'BEGIN\n1\nEND'
	clientsocket.send(messageForClient.encode())
	return 1

# 2nd attack: set g = p.
# In this case we get that A = B = 0. However since the client computes
# A before we can "inject" our bad g, we need to relay A = 0 to the
# server, and discard the A passed by the client.
# The final secret is also 0 at this point.
def DHExchangeBadServer2(clientsocket, mysocket):
	_, p = ReadOtherParameters(clientsocket)
	my_g = p

	relayedMessage = 'BEGIN\n%s\n%s\n%s\nEND' % (str(p), str(my_g), str(0))
	mysocket.send(relayedMessage.encode())

	messageForClient = 'BEGIN\n0\nEND'
	clientsocket.send(messageForClient.encode())
	return 0

# 3rd attack: set g = p - 1.
# THis is similar to the 1st attack because the final secret is 1, but
# again to achieve that we need to inject our own A instead of the
# one computed by the client.
def DHExchangeBadServer3(clientsocket, mysocket):
	_, p = ReadOtherParameters(clientsocket)
	my_g = p - 1

	relayedMessage = 'BEGIN\n%s\n%s\n%s\nEND' % (str(p), str(my_g), str(1))
	mysocket.send(relayedMessage.encode())

	messageForClient = 'BEGIN\n1\nEND'
	clientsocket.send(messageForClient.encode())
	return 1

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
		secret = DHExchangeBadServer3(clientsocket, mysocket)
		print('The computed secret is', str(secret))

		# Gets the verification message, decrypts it, and then
		# relays it to the server so nothing is suspected.
		verificationMessage = clientsocket.recv(48)
		VerifySecret(clientsocket, verificationMessage, secret)
		mysocket.send(verificationMessage)

		mysocket.close()
