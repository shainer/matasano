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

def SRPSetup(sock, email, password):
	g = 2
	k = 3
	N = int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e340'
		    '4ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f40'
		    '6b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8f'
		    'd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff', 16)

	sock.send(email.encode() + b'\n')

	a = random.randint(0, 10000)
	A = dh.modexp(g, a, N)

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

	exp = (a + u * x)
	base = (int(B) - k * dh.modexp(g, x, N))
	S = dh.modexp(base, exp, N)

	sha = hashlib.sha256()
	sha.update(str(S).encode())
	K = sha.hexdigest()

	return K, salt

if __name__ == '__main__':
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect(('localhost', 10000))

	email = input('[**] Enter email address: ')
	password = input('[**] Enter password: ')
	K, salt = SRPSetup(sock, email, password)

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