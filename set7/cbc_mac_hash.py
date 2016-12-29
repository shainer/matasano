#!/usr/bin/python3
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor

import codecs

def padPKCS7(message, k=16):
    """Apply PKCS7 padding to a message, if required."""
    if len(message) % k == 0:
        return message

    ch = k - (len(message) % k)
    return message + bytes([ch] * ch)

def GetMac(message):
    """Returns the CBC-MAC of a message with the key and IV of this challenge."""

    iv = b'\x00' * AES.block_size
    cipher = AES.new(b'YELLOW SUBMARINE', AES.MODE_CBC, iv)
    ct = cipher.encrypt(padPKCS7(message))
    return ct[-AES.block_size:]

def GetBeforeMac(message):
    """
    Returns the block before the MAC (i.e. the second-to-last one) in the
    CBC encryption of a message. We assume the ciphertext has at least two
    blocks.
    """

    iv = b'\x00' * AES.block_size
    cipher = AES.new(b'YELLOW SUBMARINE', AES.MODE_CBC, iv)
    ct = cipher.encrypt(padPKCS7(message))
    return ct[-(AES.block_size * 2):-AES.block_size]

if __name__ == '__main__':
    code = b"alert('MZA who was that?');\n"
    mac1 = GetMac(code)

    # How this works: we want to add a block at the end of codeToForge such that
    # the resulting MAC is the same as mac1 above. We end our code block with
    # a comment so that we can put anything we want afterwards.
    #
    # Given how CBC works, and the fact that we always encrypt with the same
    # algorithm, AES, and the same key, we need to append a block to codeToForge
    # such that
    #   beforeMac1 XOR last-block-of-code = mac2 XOR block-to-insert
    # where beforeMac1 is the second-to-last block in the ciphertext of |code|
    # (the one before the MAC), last-block-of-code is the last block in the
    # plaintext |code|, mac2 is the MAC of |codeToForge| below, and block-to-insert
    # is what we are trying to achieve. With XOR arithmetics we get:
    #
    # block-to-insert = beforeMac1 XOR last-block-of-code XOR mac2.
    #
    # (NOTE: to be completely realistic, the new block we find should be
    # valid ASCII; we do not enforce that here, perhaps I'll do it for a
    # later improvement).

    codeToForge = b"alert('Ayo, the Wu is back!');//"
    mac2 = GetMac(codeToForge)

    pt1 = padPKCS7(code)[-AES.block_size:]
    piece = strxor(pt1, GetBeforeMac(code))

    extension = strxor(mac2, piece)
    # Note that here we do not need to pad, if we needed to, it needs to be
    # applied here and not to the whole collision to repeat the same CBC
    # process.
    collision = padPKCS7(codeToForge) + extension

    macCollision = GetMac(collision)
    if macCollision == mac1:
        print('Collision successfully found:', collision)
    else:
        print('Collision not found, first MAC is %s but second MAC is %s' %
              (codecs.encode(mac1, 'hex'), codecs.encode(macCollision, 'hex')))
