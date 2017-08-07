#!/usr/bin/python3

import collections
from Crypto.Cipher import AES
from ch19 import EncryptWithFixedNonce
from ch19 import IsReadable

# Set 3, challenge 20: break fixed-nonce CTR statistically.

# From http://www.data-compression.com/english.html. This assigns a "frequency
# score" to each character in the English alphabet, plus space. It's good
# enough for our purposes, although it ignores some other common punctuation.
CHAR_FREQUENCIES = collections.defaultdict(int, {
    'a': 0.0651738,
    'b': 0.0124248,
    'c': 0.0217339,
    'd': 0.0349835,
    'e': 0.1041442,
    'f': 0.0197881,
    'g': 0.0158610,
    'h': 0.0492888,
    'i': 0.0558094,
    'j': 0.0009033,
    'k': 0.0050529,
    'l': 0.0331490,
    'm': 0.0202124,
    'n': 0.0564513,
    'o': 0.0596302,
    'p': 0.0137645,
    'q': 0.0008606,
    'r': 0.0497563,
    's': 0.0515760,
    't': 0.0729357,
    'u': 0.0225134,
    'v': 0.0082903,
    'w': 0.0171272,
    'x': 0.0013692,
    'y': 0.0145984,
    'z': 0.0007836,
    ' ': 0.1918182
})

def IsUpper(byte):
    return chr(byte) >= 'A' and chr(byte) <= 'Z'

def RecoverPlaintexts(ciphertextes):
    plaintextes = [''] * len(ciphertextes)
    allKeyBytes = range(0, 256)

    # Stores the reconstructed key, as an array of bytes.
    maxScoreWholeKey = []

    # Explanation: to recover byte 1, we try all possible key bytes: for
    # every potential key byte, we compute the score by XORing the byte with
    # byte 1 of each ciphertext and adding all the individual scores up. The
    # key byte with the highest final score wins and is stored as the "cracked"
    # key byte for that position.
    #
    # Due to how the CTR keystream is generated, if I encrypt a text of length
    # 53, the key has also size 53. Therefore we need to crack it byte by byte,
    # we cannot try all key combinations.
    #
    # There is some adjustment because this does not actually work for the
    # first character: the if condition basically makes sure that the plaintext
    # byte we get with the key is always an uppercase letter or the character
    # "'" (apostrophe). I thought of using this heuristics by looking at the
    # recovered plaintexts in which the first character was gibberish. A little
    # trick that makes it more similar to challenge 19 :-)

    for ctIndex in range(len(ciphertextes[0])):
        maxScore = -1
        maxScoreKey = -1

        for keyByte in allKeyBytes:
            byteScore = 0

            for ct in ciphertextes:
                possiblePT = ct[ctIndex] ^ keyByte

                if ctIndex == 0 and not IsUpper(possiblePT) and not chr(possiblePT) == "'":
                    byteScore = -1
                    break

                # Very low score for non-readable characters.
                if not IsReadable(possiblePT):
                    byteScore = -100
                    break

                # This adds 0 if the character does not exist in the dictionary.
                byteScore += CHAR_FREQUENCIES[chr(possiblePT)]

            if byteScore > maxScore:
                maxScore = byteScore
                maxScoreKey = keyByte

        maxScoreWholeKey.append(maxScoreKey)

    index = 0
    for ct in ciphertextes:
        for ctByteIndex in range(len(ct)):
            plaintextes[index] += chr(ct[ctByteIndex] ^ maxScoreWholeKey[ctByteIndex])
        index += 1

    return plaintextes

if __name__ == '__main__':
    plaintextes = []

    # Read the input as byte strings.
    with open('data/20.txt', 'rb') as data:
        plaintextes = data.readlines()

    # Reuse the faulty CTR encryption from challenge 19.
    ciphertextes = EncryptWithFixedNonce(plaintextes)

    # Compute the minimum length of all ciphertextes and truncate all of them
    # to this length.
    min_len = len(ciphertextes[0])

    for ct in ciphertextes:
        if len(ct) < min_len:
            min_len = len(ct)

    truncatedCiphertexts = [ct[:min_len] for ct in ciphertextes]
    recoveredPlaintextes = RecoverPlaintexts(truncatedCiphertexts)

    # Of course we only recovered each plaintext up to min_len, but at this
    # point you can either reapply the algorithm on the longest strings, or
    # just move to guessing the rest.
    for pt in recoveredPlaintextes:
        print(pt)
