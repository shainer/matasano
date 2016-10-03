# Inspired from the implementation at
# https://github.com/rrottmann/pydsa.

import random

def _random_s(minNumber, maxNumber):
    """
    Helper function to select a random number.
    :param min: smallest random number
    :param max: largest random number
    :return: random number
    """
    return random.randint(minNumber, maxNumber - 1)

def _mod_inverse(a, b):
    """
    Helper function that calculates the Modular multiplicative inverse
    See https://en.wikipedia.org/wiki/Modular_multiplicative_inverse
    Implementation using Extended Euclidean algorithm by Eric taken from:
    http://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
    :param a: integer to calculate the mod inverse from
    :param b: the modulo to use
    :return: Modular multiplicative inverse
    """
    r = -1
    B = b
    A = a
    eq_set = []
    full_set = []
    mod_set = []

    # euclid's algorithm
    while r != 1 and r != 0:
        r = b % a
        q = b // a
        eq_set = [r, b, a, q * -1]
        b = a
        a = r
        full_set.append(eq_set)

    for i in range(0, 4):
        mod_set.append(full_set[-1][i])

    mod_set.insert(2, 1)
    counter = 0

    #extended euclid's algorithm
    for i in range(1, len(full_set)):
        if counter % 2 == 0:
            mod_set[2] = full_set[-1 * (i + 1)][3] * mod_set[4] + mod_set[2]
            mod_set[3] = full_set[-1 * (i + 1)][1]

        elif counter % 2 != 0:
            mod_set[4] = full_set[-1 * (i + 1)][3] * mod_set[2] + mod_set[4]
            mod_set[1] = full_set[-1 * (i + 1)][1]

        counter += 1

    if mod_set[3] == B:
        return mod_set[2] % B
    return mod_set[4] % B


# Taken from
# http://stackoverflow.com/questions/5486204/fast-modulo-calculations-in-python-and-ruby
# Required because any regular library blows up computing this with such huge numbers.
def modexp(g, u, p):
   """Computes s = (g ^ u) mod p
   Args are base, exponent, modulus
   (see Bruce Schneier's book, _Applied Cryptography_ p. 244)
   """
   s = 1
   while u != 0:
      if u & 1:
         s = (s * g) % p
      u >>= 1
      g = (g * g) % p
   return s


def _digits_of_n(n, b):
    """
    Return the list of the digits in the base 'b'
    representation of n, from LSB to MSB
    This helper function is used by modexp_lr_k_ary and was
    implemented by Eli Bendersky.
    http://eli.thegreenplace.net/2009/03/28/efficient-modular-exponentiation-algorithms/
    :param n: integer
    :param b: base
    :return: number of digits in the base b
    """
    digits = []
    while n:
        digits.append(int(n % b))
        n /= b
    return digits

def dsa_sign(q, p, g, x, message, k=None):
    """
    Create a DSA signature of a message
    using the private part of a DSA keypair.
    The message is integer and usually a SHA-1 hash.
    public key: q,p,g, y
    public key: q,p,g, x
    Implemented using code snippets and explanations from:
    * http://www.herongyang.com/Cryptography/DSA-Introduction-Algorithm-Illustration-p23-q11.html
    * https://en.wikipedia.org/wiki/Digital_Signature_Algorithm
    * http://www.docjar.org/html/api/org/bouncycastle/crypto/

    We add the option to inject a k to verify whether we have broken it
    correctly (see dsa_nonce). If none is passed, we generate a random
    one as per original specification.

    >>> import hashlib
    >>> import dsa
    >>> m = hashlib.sha1()
    >>> m.update("ABCDE")
    >>> message = int("0x" + m.hexdigest(), 0)
    >>> dsa_key = {
    ...     'Q': 11,
    ...     'P': 23,
    ...     'G': 4,
    ...     'pub': 8,
    ...     'priv': 7}
    >>> sig = dsa.dsa_sign(dsa_key["Q"], dsa_key["P"], dsa_key["G"], dsa_key["priv"], message)
    >>> print len(sig)
    2
    :param q: selected prime divisor
    :param p: computed prime modulus: (p-1) mod q = 0
    :param g: computed:
              1 < g < p, g**q mod p = 1
              and
              g = h**((p-1)/q) mod p
    :param x: selected: 0 < x < q
    :param message: message to sign
    :return: DSA signature (s1,s2) sometimes called (r,s)
    """
    if k is None:
        s = _random_s(1, q)
    else:
        s = k

    s1 = 0
    s2 = 0
    while True:
        m = modexp(g, s, p)
        s1 = m % q
        if s1 == 0:
            s = _random_s(1, q)
            continue

        s = _mod_inverse(s, q) * (message + x * s1)
        s2 = s % q
        if s2 == 0:
            s = _random_s(1, q)
            continue
        return (s1, s2)


def dsa_verify(s1, s2, g, p, q, y, message):
    """
    Verify the DSA signature of a message
    using the public part of a DSA keypair.
    The message is integer and usually a SHA-1 hash.
    s1,s2: DSA signature; sometimes called (r,s)
    public key: q,p,g, y
    public key: q,p,g, x
    Implemented using code snippets and explanations from:
    * http://www.herongyang.com/Cryptography/DSA-Introduction-Algorithm-Illustration-p23-q11.html
    * https://en.wikipedia.org/wiki/Digital_Signature_Algorithm
    * http://www.docjar.org/html/api/org/bouncycastle/crypto/
    >>> import hashlib
    >>> import dsa
    >>> m = hashlib.sha1()
    >>> m.update("ABCDE")
    >>> message = int("0x" + m.hexdigest(), 0)
    >>> dsa_key = {
    ...     'Q': 11,
    ...     'P': 23,
    ...     'G': 4,
    ...     'pub': 8,
    ...     'priv': 7}
    >>> sig = (2,3)
    >>> print dsa.dsa_verify(sig[0], sig[1], dsa_key["G"], dsa_key["P"], dsa_key["Q"], dsa_key["pub"], message)
    True
    :param s1: DSA signature part 1, sometimes called r
    :param s2: DSA signature part 2, sometimes called s
    :param q: selected prime divisor
    :param p: computed prime modulus: (p-1) mod q = 0
    :param g: computed:
              1 < g < p, g**q mod p = 1
              and
              g = h**((p-1)/q) mod p
    :param y: computed: y = g**x mod p
    :param message: message to verify
    :return: True or False
    """
    if not s1 > 0:
        return False
    if not s1 < q:
        return False
    if not s2 > 0:
        return False
    if not s2 < q:
        return False
    w = _mod_inverse(s2, q)
    u1 = (message * w) % q
    u2 = (s1 * w) % q
    # v = (((g**u1)*(y**u2)) % p ) % q # correct formula but slooooow!
    # because of that, we use modulo arithmetic to calculate intermediate values:
    u1 = pow(g, u1, p)
    u2 = pow(y, u2, p)
    v = u1 * u2 % p % q
    if v == s1:
        return True
    return False

