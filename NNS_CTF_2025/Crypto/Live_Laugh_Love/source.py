from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import bytes_to_long
import os

flag = b"NNS{???????????????????}"

a     = bytes_to_long(os.urandom(128))
b     = bytes_to_long(os.urandom(128))
key   = bytes_to_long(os.urandom(16))
iv    = bytes_to_long(os.urandom(16))
noise = bytes_to_long(os.urandom(16))

c = a * iv + b * key + noise

cipher = AES.new(bytes.fromhex(f"{key:x}"), AES.MODE_CBC, bytes.fromhex(f"{iv:x}"))
ct     = cipher.encrypt(pad(flag, 16)).hex()

print(f"{a  = }")
print(f"{b  = }")
print(f"{c  = }")
print(f"{ct = }") 
