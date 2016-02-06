#!/usr/bin/python

def _Padding(string, blockSize):
	"""Returns the amount of padding bytes we need to add."""
	if len(string) % blockSize == 0:
		return 0

	return blockSize - (len(string) % blockSize)


def Pkcs7(string, blockSize):
	byte_string = bytearray(string, 'ascii')
	numPadding = _Padding(string, blockSize)

	for i in range(0, numPadding):
		byte_string += bytes([numPadding])

	return byte_string

if __name__ == '__main__':
	print(Pkcs7('YELLOW SUBMARINE', 20))