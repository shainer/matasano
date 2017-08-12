#!/usr/bin/python3

from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.strxor import strxor

class Server(object):
    def __init__(self):
        self._key = Random.new().read(AES.block_size)
        self._iv = self._key
        print('[**] Random key is', self._key)

    def encrypt(self, plaintext):
        """CBC encryption."""
        cipher = AES.new(key=self._key, mode=AES.MODE_ECB)

        # The full URL is not necessary for this setup, so I am just encrypting
        # the plaintext as it is. I don't even need to support padding.
        prev_ct = self._iv
        block_index = 0
        ciphertext = b''

        # The loop simulates encryption through AES in CBC mode.
        while block_index < len(plaintext):
            block = plaintext[block_index : block_index + AES.block_size]
            final_block = strxor(block, prev_ct)

            cipher_block = cipher.encrypt(final_block)
            prev_ct = cipher_block
            ciphertext += cipher_block

            block_index += AES.block_size

        return ciphertext

    def decrypt(self, ciphertext):
        """CBC decryption."""
        cipher = AES.new(key=self._key, mode=AES.MODE_ECB)

        prev_ct = self._iv
        block_index = 0
        plaintext = b''

        # The loop simulates decryption through AES in CBC mode.
        while block_index < len(ciphertext):
            block = ciphertext[block_index : block_index + AES.block_size]

            prep_plaintext = cipher.decrypt(block)
            plaintext += strxor(prev_ct, prep_plaintext)
            prev_ct = block

            block_index += AES.block_size

        # Here we should check if this is all readable ASCII, and raise an
        # exception if it's not. However that part is not really necessary,
        # and converting from Exception object to byte string (instead of a
        # usual string) does not look great so let's be lazy :)
        return plaintext


if __name__ == "__main__":
    server = Server()

    # Minimal massage required here to fit exactly 3 blocks :-)
    message = b'This message should consist of exactly 3 blocks.'
    ciphertext = server.encrypt(message)

    # Why does this work? Let's call K the key (and IV), PTi the ith block
    # of the plaintext and CTi the ith block of the ciphertext.
    #
    # When I decrypt the modified ciphertext, what I get is:
    #   PT1 = IV XOR AES(K, CT1) = K XOR AES(K, CT1)
    #   PT3 = CT2 XOR AES(K, CT1) = 0 XOR AES(K, CT1)
    # where 0 is of course a block filled with 0s.
    #
    # Now PT1 XOR PT3 = K XOR 0 XOR AES(K, CT1) XOR AES(K, CT1) = K XOR 0 = K.
    # XOR is commutative, plus XORing something with itself yields 0, while
    # scoring something with 0 leaves it unchanged. And voila we got the key.
    #
    # Note that two conditions are required for this property to hold: the IV
    # is equal to the key, and the server returns the plaintext even though it
    # won't be valid ASCII.

    newMessage = ciphertext[:AES.block_size]
    newMessage += b'\x00' * AES.block_size
    newMessage += ciphertext[:AES.block_size]

    plaintext = server.decrypt(newMessage)
    block1 = plaintext[:AES.block_size]
    block3 = plaintext[AES.block_size*2 : AES.block_size*3]

    recoveredKey = strxor(block1, block3)
    print('[**] The cracked key is', recoveredKey)
