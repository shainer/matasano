#!/usr/bin/python3

# Set 3, challenge 23: Clone a MT19937 RNG from its output

from ch21 import MersenneTwister

def Untemper(y):
    y = y ^ (y >> 18)
    y = y ^ ((y << 15) & 4022730752)

    mask = 2636928640
    a = y << 7
    b = y ^ (a & mask)
    c = b << 7
    d = y ^ (c & mask)
    e = d << 7
    f = y ^ (e & mask)
    g = f << 7
    h = y ^ (g & mask)
    i = h << 7
    y = y ^ (i & mask)

    z = y >> 11
    x = y ^ z
    s = x >> 11
    y = y ^ s
    return y

def FindStateFromOutputs(realOutputs):
	state = []
	isFirst = True

	for output in realOutputs:
		state.append(Untemper(output))

	return state

if __name__ == '__main__':
	realMt = MersenneTwister(10)
	realOutputs = []

	for i in range(0, 624):
		realOutputs.append(realMt.randomNumber())

	print('First 10 outputs of the real generator: %s' % (str(realOutputs[:10])))

	# Reconstruct the internal state array from the random outputs.
	state = FindStateFromOutputs(realOutputs)
	clonedMt = MersenneTwister(seed=10, injectedState=state)
	clonedOutputs = []

	# Generates again all numbers depending on the current state
	# from the cloned generator.
	for i in range(0, 624):
		clonedOutputs.append(clonedMt.randomNumber())

	print('First 10 outputs of the cloned generator: %s' % (str(clonedOutputs[:10])))

	# If the match, success.
	if realOutputs == clonedOutputs:
		print('[**] Successfully cloned the Mersenne Twister generator.')
	else:
		print('[**] The outputs are not the same.')
