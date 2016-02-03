import unittest
import utils

class testUtils(unittest.TestCase):

	def testHexToBin(self):
		self.assertEqual('10101011', utils.hex_to_bin('ab'))

	def testHexToBin_Invalid(self):
		self.assertRaises(
			utils.InvalidArgumentError,
			utils.hex_to_bin, 'gggg')

	def testBinToHex(self):
		self.assertEqual('ab', utils.bin_to_hex('10101011'))

	def testBinToHex_Incomplete(self):
		self.assertEqual('a', utils.bin_to_hex('1010101'))

	def testBinToHex_Invalid(self):
		self.assertRaises(
			utils.InvalidArgumentError,
			utils.bin_to_hex, '1012')

	def testBase64ToBin(self):
		self.assertEqual('010011010110000101101110',
						 utils.base64_to_bin('TWFu'))

	def testBase64ToAscii(self):
		self.assertEqual('Man', utils.base64_to_ascii('TWFu'))

	def testHammingDistance(self):
		self.assertEqual(37, utils.HammingDistanceAscii(
			'this is a test', 'wokka wokka!!!'))