#!/usr/bin/python3

from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.strxor import strxor

def GenerateTransaction(aSender, aDest, amount):
    t = 'from=%s&to=%s&amount=%s' % (aSender, aDest, str(amount))
    # Converts to byte string.
    return str.encode(t)

# Computes CBC-MAC.
def ComputeMac(message, cipher):
    ct = cipher.encrypt(message)
    return ct[-AES.block_size:]

# Here we just build the request, assume we send it to the server and
# handle their response too :)
def SendMessage(message):
    iv = Random.new().read(AES.block_size)
    key = b'Sixteen byte key'

    cipher = AES.new(key, AES.MODE_CBC, iv)
    return (message + iv + ComputeMac(message, cipher))

def VerifyRequest(request):
    mac = request[-AES.block_size:]
    iv = request[-(AES.block_size * 2):-AES.block_size]
    message = request[:-(AES.block_size * 2)]

    # Key is shared between server and client. IV is taken from the
    # request, as it's different for each message.
    cipher = AES.new(b'Sixteen byte key', AES.MODE_CBC, iv)
    myMac = ComputeMac(message, cipher)
    return (myMac == mac)

if __name__ == "__main__":
    # Assume we can send this message and it will get rejected because
    # -1 is not a valid account ID.
    firstMessage = GenerateTransaction('n.-1', 'n.20', 1000000)
    firstRequest = SendMessage(firstMessage)

    # As attackers, we sniff the request and are able to retrieve the IV
    # and MAC.
    iv = firstRequest[-(AES.block_size * 2):-AES.block_size]
    mac = firstRequest[-AES.block_size:]

    # Generate the transaction we actually want.
    forgedMessage = GenerateTransaction('n.00', 'n.20', 1000000)
    # Derive forgedIv such that:
    #   (firstMessage XOR iv) = (forgedMessage XOR forgedIv)
    # If this happens, since the key is always the same, we are guaranteed
    # this request has the same MAC as the first one.
    forgedIv = strxor(iv, strxor(firstMessage[:16], forgedMessage[:16]))

    # Create the request with the forged IV and the previous MAC.
    forgedRequest = forgedMessage + forgedIv + mac
    print('Forged request', forgedRequest)

    if VerifyRequest(forgedRequest):
        print('Forgery successful')
    else:
        print('Forgery failed')
