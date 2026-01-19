#!/usr/bin/env python3
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
import os

BLOCK_SIZE = 16

def isvalid(ct, txt):
    ct = pad(ct, BLOCK_SIZE)
    for i in range(0, len(ct), BLOCK_SIZE):
        if ct[i : i + BLOCK_SIZE] in txt:
            return False
    return True

flag = open("flag", "rb").read()
key = os.urandom(BLOCK_SIZE)
iv = os.urandom(BLOCK_SIZE)

# reversed!
encrypt = lambda pt: AES.new(key, AES.MODE_CBC, iv).decrypt(pt)
decrypt = lambda ct: AES.new(key, AES.MODE_CBC, iv).encrypt(ct)

flag_enc = encrypt(pad(flag, BLOCK_SIZE))

print("Welcome to dream's AES server")
while True:
    print("[1] Encrypt")
    print("[2] Decrypt")
    print("[3] Get Flag")

    choice = input()

    if choice == "1":
        print("Input plaintext (hex): ", end="")
        pt = bytes.fromhex(input())
        print(encrypt(pt).hex())

    elif choice == "2":
        print("Input ciphertext (hex): ", end="")
        ct = bytes.fromhex(input())
        if isvalid(ct, flag_enc):
            print(decrypt(ct).hex())
        else:
            print('Nope!')

    elif choice == "3":
        print(f"flag = {flag_enc.hex()}")

    else:
        print("Nope!")
