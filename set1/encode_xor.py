
# I should really rewrite this in C++. If anyone is reading this
# code I am sorry.
import sys
sys.path.insert(0, '/home/shainer/source/matasano/lib')
import utils

class XOREncoder(object):
	def __init__(self):
		pass

	def _ByteToPaddedBin(self, byte):
		bin_str = '{0:b}'.format(byte)

		while len(bin_str) < 8:
			bin_str = '0' + bin_str

		return bin_str

	def Encode(self, text, key):
		text_bin = ''
		key_bin = ''

		for i in range(0, len(text)):
			text_byte = ord(text[i])
			key_byte = ord(key[i % len(key)])

			text_bin += self._ByteToPaddedBin(text_byte)
			key_bin += self._ByteToPaddedBin(key_byte)
		
		res_bin = ''

		for j in range(0, len(text_bin)):
			if text_bin[j] == key_bin[j]:
				res_bin += '0'
			else:
				res_bin += '1'

		return utils.bin_to_hex(res_bin)