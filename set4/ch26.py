#!/usr/bin/python3

from ctr import DoCTR

# Set 4, challenge 26: CTR bitflipping.

def Encrypt(inputBytes):
	# Cannot cheat! :)
	if ord('=') in inputBytes:
		raise Exception('Invalid character in input text.')

	plaintext = b'comment1=cooking%20MCs;userdata='
	plaintext += inputBytes
	plaintext += b';comment2=%20like%20a%20pound%20of%20bacon'
	
	# There is no padding in CTR, so we do not need to apply/strip one.
	# Technically we should randomize the key and nonce, but we are only
	# going to encrypt once so I am not doing it.
	return DoCTR(plaintext, b'YELLOW SUBMARINE', 0)

def DecryptAndVerify(ciphertext):
	plaintext = DoCTR(ciphertext, b'YELLOW SUBMARINE', 0)
	return (b'admin=true' in plaintext)

if __name__ == '__main__':
	pt = b'adminXtrue'
	offset = 37  # offset of the X in the complete plaintext.
	ciphertext = Encrypt(pt)

	# The byte at position 'offset' in the plaintext is the XOR of the
	# same byte in the ciphertext (let's call it C) and of a byte which
	# is derived by applying AES encryption on the nonce + counter (we'll
	# call it A). This last byte is the same both when encrypting and
    # decrypting, due to how CTR works.
	# Therefore I have that A xor C = 'X'. To transform that into '=' I
	# compute 'X' xor 'X' xor '='. 'X' xor 'X' is 0, 0 xor 'something'
	# is 'something' so I get what I want. I also need to apply the same
	# thing on the left-hand side of the equation:
	# A xor C xor 'X' xor '=' = '='.
	flipped = ciphertext[offset] ^ ord('X') ^ ord('=')

	flippedCiphertext = ciphertext[:offset]
	flippedCiphertext += bytes([flipped])
	flippedCiphertext += ciphertext[offset + 1:]

	if DecryptAndVerify(flippedCiphertext):
		# Success.
		print('[**] This is an admin account.')
	else:
		print("[**] This is NOT an admin account.")
