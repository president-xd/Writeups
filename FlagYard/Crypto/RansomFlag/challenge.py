'''
[+] Encrypted Flag: 4HGJ/3Y6iekXR+FXdpdpa+ww4601QUtLGAzHO/8=
[+] Nonce: nFE+9jfXTKM=
[+] Private Key (d): 56771
[+] Private Key (n): 57833
[+] Encrypted Message: [41179, 49562, 30232, 7343, 51179, 49562, 24766, 36190, 30119, 33040, 22179, 44468, 15095, 22179, 3838, 28703, 32061, 17380, 34902, 51373, 41673, 6824, 41673, 26412, 27116, 51179, 34646, 15095, 10590, 11075, 1613, 20320, 31597, 51373, 20320, 44468, 23130, 47991, 11075, 15095, 34928, 20768, 15095, 8054]
'''


import secrets
import base64
from Crypto.Cipher import ChaCha20
from math import sqrt
import random
from random import randint

def gcd(a, b):
    if b == 0:
        return a
    else:
        return gcd(b, a % b)

def mod_inverse(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return -1

def is_prime(n):
    if n < 2:
        return False
    elif n == 2:
        return True
    else:
        for i in range(2, int(sqrt(n)) + 1, 2):
            if n % i == 0:
                return False
    return True

def generate_key_pair(p, q, key_size):
    n_min = 1 << (key_size - 1)
    n_max = (1 << key_size) - 1
    primes = [2]
    start = 1 << (key_size // 2 - 1)
    stop = 1 << (key_size // 2 + 1)

    if start >= stop:
        return []

    for i in range(3, stop + 1, 2):
        for prime in primes:
            if i % prime == 0:
                break
        else:
            primes.append(i)

    while primes and primes[0] < start:
        del primes[0]

    while primes:
        p = random.choice(primes)
        primes.remove(p)
        q_values = [q for q in primes if n_min <= p * q <= n_max]
        if q_values:
            q = random.choice(q_values)
            break

    n = p * q
    phi = (p - 1) * (q - 1)

    e = random.randrange(1, phi)
    g = gcd(e, phi)

    while True:
        e = random.randrange(1, phi)
        g = gcd(e, phi)
        d = mod_inverse(e, phi)
        if g == 1 and e != d:
            break

    public_key = (e, n)
    private_key = (d, n)

    return public_key, private_key

def layer3_encryption(plaintext, public_key):
    e, n = public_key
    ciphertext = [pow(ord(c), e, n) for c in plaintext]
    return ciphertext

def layer1_encryption(plaintext, key):
    cipher = ChaCha20.new(key=key)
    nonce = base64.b64encode(cipher.nonce).decode('utf-8')
    ciphertext = base64.b64encode(cipher.encrypt(plaintext.encode())).decode('utf-8')
    return ciphertext, nonce


if __name__ == "__main__":
    flag_input = input("Enter the flag: ")

    # Layer 1
    chacha_key = secrets.token_bytes(32)
    encrypted_flag, nonce = layer1_encryption(flag_input, chacha_key)
    print(f"[+] Encrypted Flag: {encrypted_flag}")
    print(f"[+] Nonce: {nonce}")

    # Layer 2
    xor_key = "0x1337" 
    obfuscated_key = bytearray(chacha_key[i] ^ ord(xor_key[i % len(xor_key)]) for i in range(len(chacha_key)))

    # Layer 3
    prime1 = randint(1, 1000)
    prime2 = randint(1, 1000)
    public_key, private_key = generate_key_pair(prime1, prime2, 2**4)
    print(f"[+] Private Key (d): {private_key[0]}")
    print(f"[+] Private Key (n): {private_key[1]}")
    encrypted_message = layer3_encryption(base64.b64encode(obfuscated_key).decode('utf-8'), public_key)
    print(f"[+] Encrypted Message: {encrypted_message}")

