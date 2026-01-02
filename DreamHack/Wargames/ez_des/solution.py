import requests
from Crypto.Cipher import DES
import random

# Configuration
URL = "http://host8.dreamhack.games:20964"
BLOCK_SIZE = 8
NUM_BLOCKS = 50

# Step 1: Download keys
print("[*] Downloading keys...")
keys_resp = requests.get(f"{URL}/keys")
keys = [bytes.fromhex(line.strip()) for line in keys_resp.text.strip().split('\n') if line.strip()]
print(f"[+] Got {len(keys)} keys")

# Step 2: Download ciphertext and get seed from header
print("[*] Downloading ciphertext...")
ct_resp = requests.get(f"{URL}/download")
ciphertext = ct_resp.content
seed = int(ct_resp.headers.get('X-Used-Seed', 0))
print(f"[+] Got ciphertext: {len(ciphertext)} bytes")
print(f"[+] Seed: {seed}")

# Step 3: Recreate the shuffled key order
idxs = list(range(NUM_BLOCKS))
random.seed(seed)
random.shuffle(idxs)
print(f"[+] Shuffled indices: {idxs[:10]}...")

# Step 4: Split ciphertext into blocks
ct_blocks = [ciphertext[i:i+BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]
print(f"[+] {len(ct_blocks)} ciphertext blocks")

# Step 5: Decrypt each block
# Note: triple_des_ede with same key = E(D(E(pt))) = E(pt) (single DES)
def triple_des_ede_decrypt(block, key):
    # Reverse of E(D(E(pt))) with same key
    # D(E(D(ct))) = D(ct) since E(D(x)) = x when same key
    d1 = DES.new(key, DES.MODE_ECB).decrypt(block)
    d2 = DES.new(key, DES.MODE_ECB).encrypt(d1)
    d3 = DES.new(key, DES.MODE_ECB).decrypt(d2)
    return d3

plaintext_blocks = []
for i, ct_block in enumerate(ct_blocks):
    key = keys[idxs[i]]
    pt_block = triple_des_ede_decrypt(ct_block, key)
    plaintext_blocks.append(pt_block)

plaintext = b''.join(plaintext_blocks)

# Step 6: Extract flag (remove padding)
print(f"\n[*] Decrypted plaintext:")
print(plaintext)

# Find the flag
flag = plaintext.rstrip(b'A')
print(f"\n[+] Flag: {flag.decode()}")
