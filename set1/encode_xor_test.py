import unittest
import encode_xor

class testEncodeXor(unittest.TestCase):

	@classmethod
	def setUpClass(cls):
		cls.encoder = encode_xor.XOREncoder()

	def testEncode(self):
		text = ('Burning \'em, if you ain\'t quick and nimble\n'
			    'I go crazy when I hear a cymbal')

		self.assertEqual(
			'0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a'
			'26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027'
			'630c692b20283165286326302e27282f',
			self.encoder.Encode(text, 'ICE'))