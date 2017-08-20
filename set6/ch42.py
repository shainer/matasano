#!/usr/bin/python3

import binascii
import math
import decimal
import rsa
import re
import hashlib

# Set 6, challenge 42: Bleichenbacher's e=3 RSA Attack.

# The signatures must contain a standard code identifying the hash algorithm
# used. This is the code for sha256. Source: https://www.ietf.org/rfc/rfc3447.txt
ASN1_GOOP = b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'

# We need to use large keysizes to have some room for padding, which then becomes
# room for garbage in our forged signature. Remember that the length of the signature
# must be equal to that of the RSA modulus.
KEY_BITSIZE = 2048
KEY_BYTESIZE = 2048 // 8

def IntegerToBytes(x, expectedLen=None):
    """Transforms an integer into the corresponding byte string.

    If expectedLen is not None, the string is padded on the left with 0 bytes
    until it reaches the expected length; if it was larger to begin with, an
    error is raised.
    """
    data = x.to_bytes((x.bit_length() + 7) // 8, 'big')

    if expectedLen is None:
        return data

    if len(data) > expectedLen:
        raise Exception('Integer too large')

    if len(data) < expectedLen:
        data = b'\x00' * (expectedLen - len(data)) + data

    return data

def BytesToInteger(s):
    return int(binascii.hexlify(s), 16)

def sha256(data):
	hasher = hashlib.sha256()
	hasher.update(data)
	return hasher.digest()

def CheckSignatureWeak(pubKey, message, signature):
    """Weak signature checking."""
    e, n = pubKey
    k = KEY_BYTESIZE

    if len(signature) != k:
        return False

    s = BytesToInteger(signature)
    m = rsa.modexp(s, e, n)

    try:
        encodedMessage = IntegerToBytes(m, k)
    except Exception as ex:
        print('Failed conversion to bytes:', str(ex))
        return False

    H = sha256(message)
    # This is probably the most common way this bug can manifest: we have a
    # regular expression that only verifies there is at least one '\xff' byte
    # in the padding, but does not state how many are expected. Moreover, it
    # does not check while this regexp covers the full string, allowing for
    # signatures, like ours, with garbage appended after the hash.
    if re.match(b'\x00\x01' + b'[\xff]+' + b'\x00' + re.escape(ASN1_GOOP + H), encodedMessage):
        return True

    return False

# Source: https://tools.ietf.org/html/rfc3447#section-9.2
def PKCS1_v1_5_ENCODE(M):
    H = sha256(M)
    T = ASN1_GOOP + H

    # Pad enough to get to the same length in bytes as the public modulo n.
    padding = (KEY_BYTESIZE - len(T) - 3) * b'\xff'
    EM = b'\x00\x01' + padding + b'\x00' + T
    return EM

def RSASign(message, privKey):
    """Compute a proper signature for the message, with the private key."""
    n, d = privKey

    encodedMessage = PKCS1_v1_5_ENCODE(message)

    # Occasionally the string encoded in s turns out to be 257 bytes, instead
    # of the 256 we expect, and this throws an error. I suspect the key pair
    # generation is a bit wonky...
    m = BytesToInteger(encodedMessage)
    s = rsa.Decrypt(privKey, m)
    signature = IntegerToBytes(s, KEY_BYTESIZE)
    return signature

def cube_root(x):
    """Required because the usual x ^ 1/3 does not work with big integers."""
    decimal.getcontext().prec = 2 * len(str(x))
    power = decimal.Decimal(1) / decimal.Decimal(3)
    x = decimal.Decimal(str(x))
    root = x ** power

    integer_root = root.quantize(decimal.Decimal('1.'), rounding=decimal.ROUND_DOWN)
    return int(integer_root)

# Taken from Hal Finney's summary at https://www.ietf.org/mail-archive/web/openpgp/current/msg00999.html,
def ForgeSignature(message, pubKey):
    e, n = pubKey

    H = sha256(message)
    D = BytesToInteger(ASN1_GOOP + H)
    Dbits = (len(H) + len(ASN1_GOOP) + 1) * 8

    # Strangely enough, Finney assumes N to be a power of 3, but here it's not
    # and it still works.
    N = (2 ** Dbits) - D
    # The -4 is to eliminate the bytes that need to be there, 00 01 at the
    # start of the signature, and FF 00 just before ASN1_GOOP.
    X = (KEY_BYTESIZE - len(H) - len(ASN1_GOOP) - 4) * 8

    # We can fit anything into the  X bits leftover for garbage, so we pick the
    # largest number we can fit.
    garbage = 2 ** X - 1
    # In the writeup, the key bit size gets 15 bits removed; here I do the same.
    maxBlock = 2 ** (KEY_BITSIZE - 15) - N * (2 ** X) + garbage

    sigNum = cube_root(maxBlock)
    signature = IntegerToBytes(sigNum, KEY_BYTESIZE)
    return signature

if __name__ == '__main__':
    pubKey, privKey = rsa.GenerateRSAPair(KEY_BITSIZE)
    message = b'real message'
    signature = RSASign(message, privKey)

    assert CheckSignatureWeak(pubKey, message, signature), 'Real signature did not verify!'
    print('[**] Real signature generated and verified correctly.')

    newMessage = b'hi mom'
    forgedSig = ForgeSignature(newMessage, pubKey)
    assert CheckSignatureWeak(pubKey, newMessage, forgedSig), 'Forged signature did not verify!'
    print('[**] Forged signature verified.')
