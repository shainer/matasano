#!/usr/bin/python3

# Set 3, challenge 20: Implement the MT19937 Mersenne Twister RNG.

class MersenneTwister(object):
	# Algorithm constants for MT19937.
	# Degree of recurrence (after this many calls to randomNumber,
	# the cycle begins anew).
	N = 624

	def __init__(self, seed, injectedState=None):
		"""If an injected state is defined, we put that into the state array
		and set the index to 0. Otherwise, we generate a new proper state from
		the seed and twist it when required."""
		self.index = self.N
		self.state = [0] * self.index

		if injectedState is None:
			self.state[0] = seed

			for i in range(1, self.index):
					self.state[i] = int(
						1812433253 * (self.state[i - 1] ^ (self.state[i - 1] >> 30))
						+ i) & 0xFFFFFFFF

		else:
			self.state = injectedState
			self.index = 0

	def randomNumber(self):
		if self.index >= self.N:
			self._twist()

		y = self.state[self.index]

		# Right shift by 11 bits
		y = y ^ y >> 11
		# Shift y left by 7 and take the bitwise and of 2636928640
		y = y ^ y << 7 & 2636928640
		# Shift y left by 15 and take the bitwise and of y and 4022730752
		y = y ^ y << 15 & 4022730752
		# Right shift by 18 bits
		y = y ^ y >> 18

		self.index += 1
		return int(y)

	def _twist(self):
		for i in range(self.N):
		    # Get the most significant bit and add it to the less significant
		    # bits of the next number
		    y = int((self.state[i] & 0x80000000) +
		               (self.state[(i + 1) % self.N] & 0x7fffffff))
		    self.state[i] = self.state[(i + 397) % self.N] ^ y >> 1

		    if y % 2 != 0:
		        self.state[i] = self.state[i] ^ 0x9908b0df
		self.index = 0


if __name__ == '__main__':
	print('[**] Let\'s generate a few numbers.')
	mt = MersenneTwister(500)

	for i in range(10):
		print(mt.randomNumber())
