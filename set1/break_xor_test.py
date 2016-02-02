import break_xor
import unittest

class testBreakXor(unittest.TestCase):

	def testHammingDistance(self):
		self.assertEqual(37, break_xor.HammingDistance(
			'this is a test', 'wokka wokka!!!'))

	def testBase64ToBin(self):
		self.assertEqual('010011010110000101101110',
			break_xor.base64_to_bin('TWFu'))

