import os
from Crypto.Cipher import AES
print("With the Secure Server 2, sharing secrets is safer than ever! We now support double encryption with AES!")
enc = bytes.fromhex(input("Enter the secret, encrypted twice with your keys (in hex): ").strip())
# Our proprietary key generation method, used by the server and John Doe himself!
k3 = b'f8' # Obviously not the actual key
k4 = b'd}' # Obviously not the actual key
# flag = secret_message + k1 + k2 + k3 + k4 (where each key is 2 bytes)
keys = [k3,k4]
final_keys = []
for key in keys:
    assert len(key) == 2 # 2 byte key into binary
    final_keys.append(bin(key[0])[2:].zfill(8)+bin(key[1])[2:].zfill(8))

cipher = AES.new(final_keys[0].encode(), mode=AES.MODE_ECB)
cipher2 = AES.new(final_keys[1].encode(), mode=AES.MODE_ECB)
enc2 = cipher2.encrypt(cipher.encrypt(enc)).hex()
print(f"Quadriple encrypted secret (in hex): {enc2}")
dec = bytes.fromhex(input("Decrypt the above with your keys again (in hex): ").strip())
secret = cipher.decrypt(cipher2.decrypt(dec))
print("Secret received!")
