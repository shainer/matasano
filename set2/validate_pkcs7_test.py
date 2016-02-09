import unittest
import validate_pkcs7 as vp

class ValidatePkcs7Test(unittest.TestCase):

	def testStripSuccess(self):
		self.assertEqual(
			'ICE ICE BABY',
			vp.strip_pkcs7('ICE ICE BABY\x04\x04\x04\x04'))

	def testInvalidLength(self):
		self.assertRaises(
			Exception,
			vp.strip_pkcs7, 'ICE ICE BABY')

	def testInvalidPadding(self):
		self.assertRaises(
			Exception,
			vp.strip_pkcs7, 'ICE ICE BABY\x05\x05\x05\x05')