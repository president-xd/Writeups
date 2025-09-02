#!/usr/local/bin/python

import signal, os, hashlib

def xor(A, B):
    return bytes([a ^ b for a, b in zip(A, B)])

def sub(x):
    return (pow(int.from_bytes(x, 'big'), -1, (2**24 +  43)) % 2**24).to_bytes(3, 'big')

def key_schedule(key):
    h = hashlib.sha256(key).digest()
    return [key[:3], key[3:], h[:6]]

def encrypt(pt, key):
    assert len(pt) == 6
    assert len(key) == 6
    k0, k1, k2 = key_schedule(key)
    u1, u2 = xor(pt[:3], k0), xor(pt[3:], k1)
    v1, v2 = sub(u1), sub(u2)
    ct = xor(v1 + v2, k2)
    return ct

def main():
    key = os.urandom(6)
    for _ in range(2):
        pt = bytes.fromhex(input('Plaintext (hex): '))
        ct = encrypt(pt, key)
        print('Ciphertext:', ct.hex())
    key_guess = bytes.fromhex(input('Key (hex): '))
    if key == key_guess:
        flag = open('flag.txt', 'r').read().strip()
        print(flag)
    else:
        print('Not quite!')

if __name__ == '__main__':
    signal.alarm(100)
    main()
