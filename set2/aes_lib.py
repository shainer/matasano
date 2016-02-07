import base64
from Crypto.Cipher import AES
from Crypto import Random
import struct

class AESCipher(object):
	def __init__(self, key, mode=AES.MODE_ECB, iv=None):
		"""Initialize a AES cipher with the given mode, and key (as a byte string)

		Parameters:
			key: the key, as a byte string (e.g. b'YELLOW SUBMARINE').
			mode: AES mode. Default: AES.MODE_ECB.
			iv: IV. If None, a random one will be generated internally.
		"""

		if iv is None:
			self._iv = Random.new().read(AES.block_size)
		else:
			self._iv = iv

		self._cipher = AES.new(key, mode=mode, IV=self._iv)

	def aes_decrypt(self, message):
		"""Decrypt a message under the cipher. The message should be a byte string."""
		return self._cipher.decrypt(message)

	def aes_encrypt(self, message):
		"""Encrypt a message under the cipher. The message should be a byte string."""
		return self._cipher.encrypt(message)

	def GenerateRandomBytes(self, size):
		"""Random byte string of given size."""
		return Random.new().read(size)


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
		text = plaintext + bytes(self.filler)

		# Pad with random bytes if the resulting text size is not a multiple
		# of the key size.
		while len(text) % AES.block_size != 0:
			text += AESCipher.GenerateRandomBytes(self, 1)

		return AESCipher.aes_encrypt(self, text)