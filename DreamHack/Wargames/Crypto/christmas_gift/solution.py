from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import random

# PNG file header - first 8 bytes are always: 89 50 4E 47 0D 0A 1A 0A
PNG_HEADER = b'\x89PNG\r\n\x1a\n'

def derive_key(s):
    """Derive AES key from first 4 bytes of plaintext"""
    random.seed(
        (s ^ 0x5a5a5a5a) ^ (~s & 0xffffffff) ^ ((s << 13) & 0xffffffff) ^ ((s >> 7) & 0xff) * 0x1010101
    )
    return bytes(
        (random.getrandbits(128) >> (i * 8)) & 255 ^ (s >> (i * 3) & 0xff) ^ ((s << (i % 5)) & 0xff)
        for i in range(15, -1, -1)
    )

def derive_iv(d):
    """Derive IV from first 4 bytes of plaintext"""
    t = bytes([
        d[0],
        ((d[2] ^ d[3]) * 57 + 131) & 255,
        ((d[3] << 3) ^ (d[2] >> 5) ^ 0b10101010) & 255,
        (((v := d[2]) >> (v % 7)) | (v << (8 - v % 7))) & 255,
        (((v := d[3]) >> (v % 7)) | (v << (8 - v % 7))) & 255
    ])
    return t + b'\x00' * (16 - len(t))

def decrypt(ciphertext, prefix):
    """Decrypt using known 4-byte prefix"""
    s = int.from_bytes(prefix[:4], 'big')
    key = derive_key(s)
    iv = derive_iv(prefix[:4])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(ciphertext)

# Read encrypted PNG
with open('flag.png', 'rb') as f:
    ciphertext = f.read()

print(f"[*] Ciphertext length: {len(ciphertext)} bytes")

# PNG header is known - first 4 bytes: \x89PNG
prefix = PNG_HEADER[:4]
print(f"[*] Using PNG header prefix: {prefix.hex()} ({prefix})")

# Decrypt
plaintext = decrypt(ciphertext, prefix)

# Verify PNG header
if plaintext[:8] == PNG_HEADER:
    print("[+] PNG header verified!")
    # Remove padding manually since we know it's valid
    try:
        plaintext = unpad(plaintext, 16)
    except:
        # If unpad fails, try to find valid PNG end
        pass
    
    # Save decrypted PNG
    with open('decrypted_flag.png', 'wb') as f:
        f.write(plaintext)
    print("[+] Saved decrypted image to decrypted_flag.png")
    
    # Try to find flag in the image data (sometimes embedded as text)
    if b'DH{' in plaintext:
        start = plaintext.find(b'DH{')
        end = plaintext.find(b'}', start) + 1
        print(f"[+] Flag found in raw data: {plaintext[start:end].decode()}")
else:
    print(f"[-] Decryption failed, first bytes: {plaintext[:16].hex()}")
    print(f"[-] Expected PNG header: {PNG_HEADER.hex()}")
