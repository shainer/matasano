# README #

Solutions for the Matasano crypto challenges as described at http://cryptopals.com .

All problems are solved in Python 3. [pycrypto](https://pypi.python.org/pypi/pycrypto) has been used
as a library for common algorithms and utilities. 

## What's missing

The solution to [MD4 collisions](http://cryptopals.com/sets/7/challenges/55) from set 7 is not complete.
This is due to me getting bored and moving to set 8 early. I plan to revisit it once I finish set 8, which
might take a while.

## Walkthroughs

When I started this repository I also started a [walkthrough](https://www.gitbook.com/book/shainer/matasano-crypto-challenges-walkthrough/details) on
GitBook. The walkthrough fell behind quite soon (it does not explain all the solutions I have actually implemented), and to be honest I am not sure
if I will ever complete it. However some explanations on more advanced challenges can be found on some blog posts I published:

- [Overview of DSA](https://shainer.github.io/crypto/python/matasano/2016/10/07/dsa.html)
- [Cloning the Mersenne Twister generator](https://shainer.github.io/crypto/python/matasano/random/2016/10/27/mersenne-twister-p2.html)
- [Challenge 51, or the CRIME attack](https://shainer.github.io/crypto/2017/01/02/crime-attack.html)
- [Challenges 52 and 53, or how to multiply hash collisions](https://shainer.github.io/crypto/2017/01/22/multiplying-hash-collisions.html)

The code should also be reasonably commented (if I can say so myself :-)).

## Set 8

As I explained on my blog, the challenge authors have asked not to share the challenges of set 8. I believe it implies not sharing the
solutions either, since they would give a pretty good insight into the original challenge. I could not find other repositories sharing them.

I asked them for permission to share the solutions here, but have not received any reply. Therefore for now they remain in a private repository;
sorry about that. I still plan to write about interesting things I learn thanks to these challenges, on the blog.
