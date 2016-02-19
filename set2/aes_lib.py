import base64
from Crypto.Cipher import AES
from Crypto import Random
import struct
from pkcs7 import Pkcs7
from pkcs7 import StripPkcs7

class AESCipher(object):
	def __init__(self, key=None, mode=AES.MODE_ECB, iv=None):
		"""Initialize a AES cipher with the given mode, and key (as a byte string)

		Parameters:
			key: the key, as a byte string (e.g. b'YELLOW SUBMARINE'). If None,
				a random one will be generated.
			mode: AES mode. Default: AES.MODE_ECB.
			iv: IV. If None, a random one will be generated internally.
		"""

		if iv is None:
			self._iv = self.GenerateRandomBytes(AES.block_size)
		else:
			self._iv = iv

		if key is None:
			self._key = self.GenerateRandomBytes(AES.block_size)
		else:
			self._key = key

		self.mode = mode
		self._cipher = AES.new(key=self._key, mode=self.mode, IV=self._iv)

	def aes_decrypt(self, message):
		"""Decrypt a message under the cipher. The message should be a byte string."""
		return self._cipher.decrypt(message)

	def aes_encrypt(self, message):
		"""Encrypt a message under the cipher. The message should be a byte string."""
		return self._cipher.encrypt(message)

	def aes_pad_and_encrypt(self, message):
		"""Encrypts a message under the cipher, adding PKCS7 padding if required."""
		return self.aes_encrypt(Pkcs7(message, AES.block_size))

	def aes_decrypt_and_depad(self, message):
		"""Decrypts a message under the cipher, removing and verifying PKCS7 padding."""
		return StripPkcs7(self.aes_decrypt(message), AES.block_size)

	def GenerateRandomBytes(self, size):
		"""Random byte string of given size."""
		return Random.new().read(size)

	def _ByteXOR(self, s1, s2):
		"""Computes the XOR between two byte strings."""
		assert len(s1) == len(s2)
		res = b''

		for i in range(0, len(s1)):
			# Each byte is converted to a number, XORed, and then
			# converted back.
			n1 = s1[i]
			n2 = s2[i]
			res += bytes([n1 ^ n2])

		return res

	def SimulateCBCEncryption(self, plaintext):
		assert self.mode == AES.MODE_ECB

		prev_ct = self._iv
		block_index = 0
		ciphertext = b''

		# The loop simulates decryption through AES in CBC mode.
		# In such mode, the ciphertext is divided in blocks the size
		# of the key. Each block is decrypted, then the plaintext is XORed
		# with the previous ciphertext block. To initialize the algorithm,
		# a random IV (initialization vector) is used.
		while block_index < len(plaintext):
			block = plaintext[block_index : block_index + AES.block_size]
			final_block = self._ByteXOR(block, prev_ct)

			cipher_block = self.aes_encrypt(final_block)
			prev_ct = cipher_block
			ciphertext += cipher_block

			block_index += AES.block_size

		return ciphertext

	def SimulateCBCDecryption(self, ciphertext):
		"""Implement decryption with CBC mode, without relying on the
		underlying library.

		Only works if the current mode is ECB. No padding is applied.
		"""
		assert self.mode == AES.MODE_ECB

		prev_ct = self._iv
		block_index = 0
		plaintext = b''

		# The loop simulates decryption through AES in CBC mode.
		# In such mode, the ciphertext is divided in blocks the size
		# of the key. Each block is decrypted, then the plaintext is XORed
		# with the previous ciphertext block. To initialize the algorithm,
		# a random IV (initialization vector) is used.
		while block_index < len(ciphertext):
			block = ciphertext[block_index : block_index + AES.block_size]

			prep_plaintext = self.aes_decrypt(block)
			plaintext += self._ByteXOR(prev_ct, prep_plaintext)
			prev_ct = block

			block_index += AES.block_size
		return plaintext


class RandomizedCipher(AESCipher):

	def __init__(self):
		self.key = AESCipher.GenerateRandomBytes(self, AES.block_size)
		AESCipher.__init__(self, self.key)

		base64_filler = ('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg'
						 'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq'
						 'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg'
						 'YnkK')
		self.filler = base64.b64decode(base64_filler)

	def Encrypt(self, plaintext):
		"""Returns the encrypted text."""
		text = plaintext + self.filler

		return AESCipher.aes_pad_and_encrypt(self, text)