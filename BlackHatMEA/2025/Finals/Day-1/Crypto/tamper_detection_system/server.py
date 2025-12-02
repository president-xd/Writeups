#!/usr/local/bin/python
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.strxor import strxor

try:
    with open("/flag.txt", "rb") as f:
        FLAG = f.read()
except FileNotFoundError:
    FLAG = b"FLAG{******** REDACTED ********}"

def encrypt(plaintext: bytes, key: bytes, nonce: bytes, associated_data: bytes = b""):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(associated_data)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, tag

def decrypt(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes, associated_data: bytes = b""):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(associated_data)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

def query(ciphertext: bytes, aad: bytes, key: bytes, tag: bytes, nonce: bytes):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try: 
        cipher.update(aad)
        cipher.decrypt_and_verify(ciphertext, tag)
        return True
    except:
        return False

nonce = get_random_bytes(12)
key = get_random_bytes(32)

flag_ciphertext, flag_tag = encrypt(FLAG, key, nonce, b"")
print("flag ciphertext: ", base64.b64encode(flag_ciphertext).decode())
print("flag tag: ", base64.b64encode(flag_tag).decode())

user_plaintext = input("your_text1:")
ciphertext, tag = encrypt(user_plaintext.encode(), key, nonce, b"")
print("tag1: ", base64.b64encode(tag).decode())

user_plaintext = input("your_text2:")
ciphertext, tag = encrypt(user_plaintext.encode(), key, nonce, b"")
print("tag2: ", base64.b64encode(tag).decode())

while True:
    length = int(input("length:"))
    aad = base64.b64decode(input("aad: "))
    print(query(ciphertext[:length], aad, key, tag, nonce))
