#!/usr/bin/python3

import hashlib

# TODO: implement SHA1 from scratch for the fun of it.
def Sha1Sign(message):
	"""Signs the message with SHA1 and a secret prefix.
	Both the input and output are byte strings."""
	sha1 = hashlib.sha1()
	sha1.update(b'YELLOW SUBMARINE')
	sha1.update(message)
	return sha1.digest()

