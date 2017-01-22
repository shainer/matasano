#!/usr/bin/python3
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.strxor import strxor

import math

def padPKCS7(message, k=16):
    """Apply PKCS7 padding to a message, if required."""
    if len(message) % k == 0:
        return message

    ch = k - (len(message) % k)
    return message + bytes([ch] * ch)

def GetNumBlocks(message):
    return math.ceil(len(message) / AES.block_size)

def GetBlock(message, index):
    # To make it easier, I assume there are always perfectly-sized blocks
    # in the input.
    return message[index * AES.block_size:(index+1) * AES.block_size]

def CBCMac(message, iv):
    """Returns the CBC-MAC of a message with the key and IV of this challenge."""
    cipher = AES.new(b'YELLOW SUBMARINE', AES.MODE_CBC, iv)
    ct = cipher.encrypt(padPKCS7(message))
    return ct[-AES.block_size:]

def CBCMacWithStates(message, iv):
    M_states = []

    paddedMessage = padPKCS7(message)
    intermediateMessage = b''
    currentState = iv

    for bIndex in range(GetNumBlocks(paddedMessage)):
        intermediateMessage += GetBlock(paddedMessage, bIndex)

        cipher = AES.new(b'YELLOW SUBMARINE', AES.MODE_CBC, currentState)
        currentState = cipher.encrypt(intermediateMessage)
        currentState = currentState[-AES.block_size:]
        M_states.append( ( bIndex, currentState ) )

    return currentState, M_states


if __name__ == '__main__':
    totalK = 4
    iv = Random.new().read(AES.block_size)
    currentState = iv

    for k in range(totalK, 0, -1):
        singleBlockMessage = Random.new().read(AES.block_size)
        singleBlockMac = CBCMac(singleBlockMessage, currentState)

        longestMessageBlockSize = (2 ** (k-1)) + 1
        longestMessage = Random.new().read( AES.block_size * (2**(k-1)) )

        dummyMac = CBCMac(longestMessage, currentState)
        lastBlock = strxor( strxor(dummyMac, singleBlockMessage), currentState )
        longestMessage += lastBlock
        secondMac = CBCMac(longestMessage, currentState)

        if singleBlockMac != secondMac:
            raise Exception('Step k=%d failed' % k) 

        print('[**] Step k=%d: success' % k)
        currentState = secondMac

    # M = Random.new().read( AES.block_size * (2**k) )
    # M_hash, M_states = CBCMacWithStates(M, iv)
    # 