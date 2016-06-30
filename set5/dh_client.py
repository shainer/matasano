#!/usr/bin/python3

from Crypto.Cipher import AES
from Crypto import Random

import diffie_hellman as dh
import hashlib
import random
import socket
import sys

# To start the verification process, we derive a private key from the
# secret, encrypt a message using AES with the secret key, and send it to
# the server. The server will verify it is able to decrypt the message.
#
# For a complete verification we should also repeat this the other
# way around and verify we are able to decrypt the server's messages.
def VerifyKey(socket, secret):
	sha1 = hashlib.sha1()
	sha1.update(str(secret).encode())
	privateKey = sha1.hexdigest()

	message = b'I am making a note here, huge success!'
	message += b'\x00' * 10
	iv = b'\x00' * AES.block_size
	cipher = AES.new(key=privateKey[:16], mode=AES.MODE_CBC, IV=iv)

	ciphertext = cipher.encrypt(message)
	socket.send(ciphertext)

def DHExchangeClient(serverHost, port):
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect((serverHost, port))

	# Usual parameters as recommended by NIST.
	pHex = ('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e340'
		    '4ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f40'
		    '6b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8f'
		    'd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff')
	p = int(pHex, 16)
	g = 2

	a = random.randint(0, p - 1)
	A = dh.modexp(g, a, p)
	B = 0

	# Sends the message in the predefined format.
	message = 'BEGIN\n%s\n%s\n%s\nEND' % (str(p), str(g), str(A))
	sock.send(message.encode())

	# Gets a similar message back from the server. See the comments
	# on dh_server which has a similar loop.
	exchange = b''
	while b'D' not in exchange:
		exchange += sock.recv(100)

	exchange = exchange.decode()
	pieces = exchange.split('\n')

	B = int(pieces[1])
	secret = dh.modexp(B, a, p)

	print('My secret is', str(secret))
	VerifyKey(sock, secret)

	sock.close()

if __name__ == '__main__':
	if len(sys.argv) != 2:
		print('Usage: ./dh_client {good|bad}')
		sys.exit(1)

	mode = sys.argv[1]
	if mode == 'good':
		DHExchangeClient('localhost', 10000)
	elif mode == 'bad':
		DHExchangeClient('localhost', 10002)
	else:
		print('Cannot recognize mode:', mode)