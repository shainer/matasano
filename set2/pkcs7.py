# PKCS7 utilities: apply and strip padding to strings.

# This also serves as solution for Set 2, Challenge 15.

def _Padding(string, blockSize):
	"""Returns the amount of padding bytes we need to add."""
	if len(string) % blockSize == 0:
		return 0

	return blockSize - (len(string) % blockSize)


def Pkcs7(string, blockSize):
	numPadding = _Padding(string, blockSize)
	paddedString = string

	for i in range(0, numPadding):
		paddedString += bytes([numPadding])

	return paddedString

def StripPkcs7(string, blockSize):
	paddingFound = False

	if len(string) % blockSize != 0:
		raise Exception('String has not been padded properly.')

	index = len(string) - 1

	lastCh = string[index]
	if lastCh > blockSize:
		return string

	num_padding = 1
	while True:
		index -= 1
		if string[index] != lastCh:
			break

		num_padding += 1

	if num_padding != lastCh:
		raise Exception('Wrong padding applied.')

	return string[:index+1]

