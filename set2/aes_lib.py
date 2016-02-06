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
