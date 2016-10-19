#!/usr/bin/python3

from mersenne_twister import MersenneTwister
import random
import time

MIN_PAUSE = 40
MAX_PAUSE = 1000

def RandWithTimestampedSeed():
	pause = random.randint(MIN_PAUSE, MAX_PAUSE)
	time.sleep(pause)

	seed = int(time.time())
	# Just to know if we did it right.
	print('[**] Leaking the seed for verification purposes: ' + str(seed))
	mt = MersenneTwister(seed)

	pause = random.randint(MIN_PAUSE, MAX_PAUSE)
	time.sleep(pause)

	return mt.randomNumber()

# I am somewhat unsure about this approach, it seems really crude.
# The other option is to perform the Mersenne Twister computation
# in reverse to return from the generated number to the seed, since
# the algorithm and parameters are common knowledge anyway.
#
# UPDATE! I have researched this in more details, and it seems the
# relationship between the seed and the first generated number is
# not 1:1, but rather there are multiple (similar) seeds that can
# give rise to the same initial number. So inversion will find one
# such seed, but it's not guaranteed to be the one you actually used.
# A few tries shows that the first 3 digits are correct, but the
# rest may not be.
def CrackSeed(generatedNumber):
	currentTime = int(time.time())

	for tries in range(0, 1000000):
		mt = MersenneTwister(currentTime)
		if mt.randomNumber() == generatedNumber:
			return currentTime

		currentTime -= 1

	return None

if __name__ == '__main__':
	num = RandWithTimestampedSeed()
	discoveredSeed = CrackSeed(num)
	print('[**] The cracked seed is ' + str(discoveredSeed))