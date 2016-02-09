#!/usr/bin/python

def strip_pkcs7(string):
	paddingFound = False

	if len(string) % 16 != 0:
		raise Exception('String has not been padded properly.')

	index = len(string) - 1

	lastCh = ord(string[index])
	if lastCh > 16:
		return string

	num_padding = 1
	while True:
		index -= 1
		if ord(string[index]) != lastCh:
			break

		num_padding += 1

	if num_padding != lastCh:
		raise Exception('Wrong padding applied.')

	return string[:index+1]
