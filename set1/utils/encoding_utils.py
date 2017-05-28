import base64
import codecs

# TODO: do this by hand.
def HexToBase64(hex_string):
    encoded = codecs.decode(hex_string, 'hex')
    return base64.b64encode(encoded)
