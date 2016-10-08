#!/usr/bin/python3

import dsa

# We do not actually run it because to do it we need to relax the DSA implementation.
# In the sign() function, the generated r, the first part of the signature, is always 0,
# which is not actually allowed by the specification. This is because when you compute
# modexp(g, u, p), you get 0^u = 0, and then 0 % p = 0 (for any u and p).
#
# If you remove the restriction and return a signature with r=0, it does not verify
# the same string it signed.
def Generator0():
	dsa_params = {
		'Q': int("0xf4f47f05794b256174bba6e9b396a7707e563c5b", 16),
 		'P': int("0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16),
		'G': 0,
	}

	privateKey, publicKey = dsa.generate_pair(dsa_params['P'], dsa_params['G'], dsa_params['Q'])

	sig = dsa.dsa_sign(dsa_params['Q'], dsa_params['P'], dsa_params['G'], privateKey, dsa.HashMessage(b'And now for something completely different'))
	print(sig)

	res = dsa.dsa_verify(sig[0], sig[1], dsa_params['G'], dsa_params['P'], dsa_params['Q'], publicKey, dsa.HashMessage(b'And now for something completely different'))
	print(res)

def GeneratorPPlus1():
	dsa_params = {
		'Q': int("0xf4f47f05794b256174bba6e9b396a7707e563c5b", 16),
 		'P': int("0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16),
	}
	dsa_params['G'] = dsa_params['P'] + 1

	privateKey, publicKey = dsa.generate_pair(dsa_params['P'], dsa_params['G'], dsa_params['Q'])

	# The generated signature is verified against any string, provided the public
	# key is correct.
	sig = dsa.dsa_sign(dsa_params['Q'], dsa_params['P'], dsa_params['G'], privateKey, dsa.HashMessage(b'Hello world!'))
	res = dsa.dsa_verify(sig[0], sig[1], dsa_params['G'], dsa_params['P'], dsa_params['Q'], publicKey, dsa.HashMessage(b'Goodbye world!'))
	if res:
		print('[**] Attack with G=P+1 successful.')
	else:
		print('[!!] Attack with G=P+1 failed.')


if __name__ == '__main__':
	# Generator0()
	GeneratorPPlus1()