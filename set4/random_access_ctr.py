#!/usr/bin/python3

import base64
import block_utils
import ctr
from Crypto.Cipher import AES
from Crypto import Random


def EditCTR(ciphertext, offset, newText, ctrObj):
	numBlocks = block_utils.GetNumBlocks(ciphertext)

	# Sanity checking.
	if offset < 0 or offset > numBlocks - 1:
		raise ValueError("Invalid offset.")

	if len(newText) != AES.block_size:
		raise ValueError("New plaintext must be 1 block in size")
	
	# Encrypt the new block of text using the value of the
	# counter for the 'offset' block of the ciphertext. The idea
	# is that newBlock will replace the block at position 'offset'
	# in the ciphertext, although here we do not perform the
	# actual substitution.
	newBlock = ctrObj.OneBlockCrypt(newText, offset)
	return newBlock

# This function is only here to recover the text as explained
# in the challenge. Of course here we need to know the key :)
def GetCTRCiphertext(sourceFilename):
	originalText = ''

	with open(sourceFilename, 'r') as input_file:
		originalText = input_file.read()

	aes = AES.new(b'YELLOW SUBMARINE', mode=AES.MODE_ECB,
		IV=Random.new().read(AES.block_size))
	plaintext = aes.decrypt(base64.b64decode(originalText))
	return ctr.DoCTR(plaintext, b'YELLOW SUBMARINE', 0)

if __name__ == '__main__':
	ciphertext = GetCTRCiphertext('data/25.txt')
	numBlocks = block_utils.GetNumBlocks(ciphertext)

	# Here we should hide the key and nonce, pretend they are both
	# generated internally to AESCtr :)
	ctrObj = ctr.AESCtr(b'YELLOW SUBMARINE', 0)
	recoveredPlaintext = ''

	# Very simple idea: to do this replacement of ciphertext
	# blocks, I need to use the same nonce and counter as in
	# the original encryption, otherwise decryption will not
	# work.
	# But doing this, I can retrieve what the corresponding
	# byte of the keystream is, and from that the original
	# plaintext block by XORin the recovered keystream with
	# the same byte in the original ciphertext. Not very
	# smart...
	for blockIndex in range(0, numBlocks):
		newBlock = EditCTR(
			ciphertext, blockIndex, b'my new plaintext', ctrObj)
		keystream = block_utils.BlockXOR(b'my new plaintext', newBlock)

		plainBlock = block_utils.BlockXOR(
			keystream, block_utils.GetSingleBlock(ciphertext, blockIndex))
		recoveredPlaintext += plainBlock.decode('ascii')

	print(recoveredPlaintext)