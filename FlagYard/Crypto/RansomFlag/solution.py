#!/usr/bin/env python3
import base64
from Crypto.Cipher import ChaCha20

# --- values from the top comment ---
ENCRYPTED_FLAG_B64 = "4HGJ/3Y6iekXR+FXdpdpa+ww4601QUtLGAzHO/8="
NONCE_B64 = "nFE+9jfXTKM="
D = 56771
N = 57833
ENCRYPTED_MESSAGE = [
    41179, 49562, 30232, 7343, 51179, 49562, 24766, 36190, 30119, 33040, 22179,
    44468, 15095, 22179, 3838, 28703, 32061, 17380, 34902, 51373, 41673, 6824,
    41673, 26412, 27116, 51179, 34646, 15095, 10590, 11075, 1613, 20320, 31597,
    51373, 20320, 44468, 23130, 47991, 11075, 15095, 34928, 20768, 15095, 8054
]
XOR_KEY_STR = "0x1337"

def rsa_decrypt_chars(cipher_list, d, n):
    # Each element is c = m^e mod n for a single ASCII char; recover m = c^d mod n
    chars = [pow(c, d, n) for c in cipher_list]
    return ''.join(chr(x) for x in chars)

def deobfuscate_key(obf_b64, xor_key_str):
    obf = base64.b64decode(obf_b64)
    k = xor_key_str.encode()
    return bytes(obf[i] ^ k[i % len(k)] for i in range(len(obf)))

def chacha20_decrypt(ct_b64, key, nonce_b64):
    ct = base64.b64decode(ct_b64)
    nonce = base64.b64decode(nonce_b64)  # PyCryptodome's ChaCha20 uses 8-byte nonces
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.decrypt(ct)

def main():
    # Layer 3: RSA -> base64 string of obfuscated key
    obf_key_b64 = rsa_decrypt_chars(ENCRYPTED_MESSAGE, D, N)
    print("[#] Obfuscated Key : ", obf_key_b64)

    # Layer 2: deobfuscate the key by XORing with "0x1337"
    chacha_key = deobfuscate_key(obf_key_b64, XOR_KEY_STR)
    print("[#] Chacha Key : ", chacha_key)

    # Layer 1: ChaCha20 decrypt to get the flag
    flag = chacha20_decrypt(ENCRYPTED_FLAG_B64, chacha_key, NONCE_B64).decode()

    print("[+] Recovered Flag:", flag)

if __name__ == "__main__":
    main()
