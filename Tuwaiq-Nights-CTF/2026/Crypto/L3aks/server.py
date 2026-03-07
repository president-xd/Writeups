#!/usr/bin/env python3

from Crypto.Util.number import getStrongPrime
import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


flag = "FlagY{Redacted}"
def encrypt_flag(secret_key):
    sha1 = hashlib.sha1()
    sha1.update(str(secret_key).encode('ascii'))
    key = sha1.digest()[:16]
    iv = os.urandom(16)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(flag.encode(),16))
    print("{ ciphertext : " + ciphertext.hex() + ", iv : " + iv.hex() + "}")

    return ciphertext, iv

p = getStrongPrime(512)
print(f"{p=}")
g = 2
a = getStrongPrime(512)
A = pow(g,a,p)
print(f"{A=}")
b = getStrongPrime(512)
B = pow(g,b,p)
print(f"{B=}")
s = pow(B,a,p)
mask = ((1 << 256) - 1 << 256) + (1 << 255)
r1 = s & mask
print(f"{r1=}")
c = getStrongPrime(512)
print(f"{c=}")
AC = pow(g,a+c,p)
s2 = pow(AC,b,p)
print(f"{AC=}")
r2 = s2 & mask
print(f"{r2=}")
encrypt_flag(s)