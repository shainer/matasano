import unittest
import fixed_xor

class testXor(unittest.TestCase):

	def testFixedXor(self):
		self.assertEqual(
			'746865206b696420646f6e277420706c6179',
			fixed_xor.fixed_xor(
				'1c0111001f010100061a024b53535009181c',
				'686974207468652062756c6c277320657965'))

	def testFixedXor_DiffLength(self):
		self.assertRaises(
			fixed_xor.InvalidArgumentError,
			fixed_xor.fixed_xor, 'a', 'bb')

	def testFixedXor_InvalidString(self):
		self.assertRaises(
			fixed_xor.InvalidArgumentError,
			fixed_xor.fixed_xor, 'a', 'g')

	def testFixedXorBinary(self):
		self.assertEqual(
			'1010', fixed_xor.fixed_xor_bins('0101', '1111'))

	def testFixedXorBinary_InvalidString(self):
		self.assertRaises(
			fixed_xor.InvalidArgumentError,
			fixed_xor.fixed_xor_bins, '1111', '3322')

if __name__ == '__main__':
	unittest.main()