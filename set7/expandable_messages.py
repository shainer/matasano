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
    return message[index * AES.block_size:(index+1) * AES.block_size]

# The choice of algorithm here is not very important. You can do this
# with any hash function in which the hash is computed from a chain of
# intermediate states.
def CBCMac(message, iv):
    cipher = AES.new(b'YELLOW SUBMARINE', AES.MODE_CBC, iv)
    ct = cipher.encrypt(padPKCS7(message))
    return ct[-AES.block_size:]

def CBCMacWithStates(message, iv):
    """Computes the CBC-MAC of a message given the IV.

    Returns a tuple with the hash and a list of tuples; the first
    element is the block index and the second is the intermediate state
    associated with that block, as a byte string.

    It is expected that this returns the same hash as CBC-MAC above
    given the same inputs.
    """
    M_states = []

    paddedMessage = padPKCS7(message)
    intermediateMessage = b''
    currentState = iv

    for bIndex in range(GetNumBlocks(paddedMessage)):
        intermediateMessage = GetBlock(paddedMessage, bIndex)

        cipher = AES.new(b'YELLOW SUBMARINE', AES.MODE_CBC, currentState)
        currentState = cipher.encrypt(intermediateMessage)
        currentState = currentState[-AES.block_size:]
        M_states.append( ( bIndex, currentState ) )

    return currentState, M_states


if __name__ == '__main__':
    totalK = 4
    iv = Random.new().read(AES.block_size)
    currentState = iv
    expandableMessages = []

    # Generates the expandable messages. At each stage we produce one
    # single block message and a longer one. We store them as a list
    # of tuples.
    for k in range(totalK, 0, -1):
        singleBlockMessage = Random.new().read(AES.block_size)
        singleBlockMac = CBCMac(singleBlockMessage, currentState)

        # If our longer block is T blocks long, we "fix" the first
        # T-1 blocks to something random. Then given the hash of
        # these dummy blocks and the singleBlockMessage we are able
        # to compute the last block such that we have a collision with
        # singleBlockMessage itself.
        longerMessageBlockSize = (2 ** (k-1)) + 1
        longerMessage = Random.new().read( AES.block_size * (2**(k-1)) )

        dummyMac = CBCMac(longerMessage, currentState)
        lastBlock = strxor( strxor(dummyMac, singleBlockMessage), currentState )
        longerMessage += lastBlock
        secondMac = CBCMac(longerMessage, currentState)

        # Verify the two blocks collide with each other.
        if singleBlockMac != secondMac:
            raise Exception('Step k=%d failed' % k) 

        print('[**] Step k=%d: success' % k)
        print('  Generated message of %d blocks' % (len(longerMessage) / AES.block_size))

        # Update the state for the next step.
        currentState = secondMac
        expandableMessages.append( ( singleBlockMessage, longerMessage ) )

    finalState = currentState

    M = Random.new().read( AES.block_size * (2**totalK) )
    print('[**] Generated random M with %d blocks' % (2**totalK))
    M_hash, M_states = CBCMacWithStates(M, iv)

    bridgeIndex = 13

    # Given the index where we want to place our bridge, compute the actual
    # bridge block knowing the input and the state we want to get to. Note
    # that we use the previous intermediate state for M to do this. 
    bridge = strxor( strxor(finalState, M_states[bridgeIndex-1][1]), GetBlock(M, bridgeIndex) )
    remainingBlocks = b''
    # Concatenate the blocks of M we need to append to our forgery.
    for i in range(bridgeIndex+1, 2**totalK):
        remainingBlocks += GetBlock(M, i)

    # Here I fix bridgeIndex and decided which expandable blocks to use manually so that the
    # prefix length was as expected. I use the longer block + shorter + shorter + longer to
    # make it more varied. It would be possible to automatically compute the set of blocks
    # to use here as an optimization problem, if you want to get fancy :)
    forgery = (expandableMessages[0][1] + expandableMessages[1][0] + expandableMessages[2][0] + expandableMessages[3][1] +
                bridge + remainingBlocks)
    print('[**] Length of the forgery is %d blocks' % (len(forgery) / AES.block_size))

    if len(forgery) != len(M):
        print('!! Error. Message and forgery have different lengths.')
    elif forgery == M:
        print('!! Error. Generated forgery and M are the same')
    else:
        forgeryHash = CBCMac(forgery, iv)

        if forgeryHash == M_hash:
            print('[**] Success')
        else:
            print('Failure. Forgery hash was %s, expected %s' % (forgeryHash, M_hash))