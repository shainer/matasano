import base64
from Crypto.Cipher import AES
from Crypto import Random
import struct

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

		self._cipher = AES.new(key=self._key, mode=mode, IV=self._iv)

	def aes_decrypt(self, message):
		"""Decrypt a message under the cipher. The message should be a byte string."""
		return self._cipher.decrypt(message)

	def aes_encrypt(self, message):
		"""Encrypt a message under the cipher. The message should be a byte string."""
		return self._cipher.encrypt(message)

	def aes_pad_and_encrypt(self, message):
		pt = message
		self.padding = 0

		while len(pt) % AES.block_size != 0:
			pt += '\x00'
			self.padding += 1
		return self.aes_encrypt(pt)

	def aes_decrypt_and_depad(self, message):
		pt = self.aes_decrypt(message)

		if self.padding:
			return pt[:-self.padding]
		return pt

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
		return AESCipher.aes_encrypt(self, text)