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