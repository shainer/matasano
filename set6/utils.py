#!/usr/bin/python3

# Taken from
# http://stackoverflow.com/questions/5486204/fast-modulo-calculations-in-python-and-ruby
# Required because any regular library blows up computing this with such huge numbers.
def modexp(g, u, p):
   """Computes s = (g ^ u) mod p
   Args are base, exponent, modulus
   (see Bruce Schneier's book, _Applied Cryptography_ p. 244)
   """
   if g == 0:
    return 0

   s = 1
   while u != 0:
      if u & 1:
         s = (s * g) % p
      u >>= 1
      g = (g * g) % p
   return s