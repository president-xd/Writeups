#!/usr/bin/env python3

import secrets

from math import gcd
from typing import List
from dataclasses import dataclass

from gmpy2 import next_prime


@dataclass
class Params:
    p: int
    s: int
    primes: List[int]
    roots: List[int]


def random_prime(nbits: int) -> int:
    rand = secrets.randbits(nbits)
    initial = (1 << (nbits - 1)) | rand

    return int(next_prime(initial))


def prime_list(n: int) -> List[int]:
    primes = [2]

    for _ in range(1, n):
        prime = int(next_prime(primes[-1]))
        primes.append(prime)

    return primes


def generate_params(nbits: int, nprimes: int) -> Params:
    p = random_prime(nbits)
    primes = prime_list(nprimes)

    while True:
        s = secrets.randbelow(p - 1)

        if gcd(p - 1, s) == 1:
            break

    roots = [pow(prime, pow(s, -1, p - 1), p) for prime in primes]

    return Params(p, s, primes, roots)


def encrypt(plaintext: int, params: Params) -> int:
    ciphertext = 1

    for i in range(len(params.roots)):
        bit = plaintext & 1
        part = pow(params.roots[i], bit, params.p)
        ciphertext = (ciphertext * part) % params.p

        plaintext >>= 1

    return ciphertext


def decrypt(ciphertext: int, params: Params) -> int:
    c = pow(ciphertext, params.s, params.p)
    plaintext = 0

    for i in range(len(params.primes)):
        bit = (gcd(params.primes[i], c) - 1) // (params.primes[i] - 1)
        plaintext += bit << i

    return plaintext


def main():
    nbits = 256
    nprimes = 64

    params = generate_params(nbits, nprimes)

    print({
        'p': params.p,
        'primes': params.primes,
        'roots': params.roots
    })

    with open('flag.txt', 'rb') as file:
        flag = file.read()

    plaintext = int.from_bytes(flag, 'big')
    ciphertexts = []

    while plaintext > 0:
        part = plaintext % (1 << nprimes)
        ciphertext = encrypt(part, params)

        assert decrypt(ciphertext, params) == part

        ciphertexts.append(ciphertext)
        plaintext >>= nprimes

    print(ciphertexts)


if __name__ == '__main__':
    main()
