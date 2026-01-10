import numpy as np
from binteger import Bin
from Crypto.Hash import SHAKE128

"""
LWE Decryption Attack Solution

The scheme:
- pk = s @ A + 2*e (mod 2^16)
- encrypt(b): c = [A @ e', pk @ e' + b]
- decrypt: sk·c & 1 where sk = [-s, 1]

Key insight: We only need s mod 2 for decryption!
pk mod 2 = (s @ A) mod 2  (since 2*e ≡ 0 mod 2)
So we solve for s mod 2 over GF(2).
"""

# Reconstruct the same A matrix
shake = SHAKE128.new(b'defund')
n = 976

crs = shake.read(np.dtype(np.uint16).itemsize * n**2)
A = np.frombuffer(crs, dtype=np.uint16).reshape((n, n))

# Load the public key and ciphertext
with open('pk', 'rb') as f:
    pk = np.frombuffer(f.read(), dtype=np.uint16)

with open('ct', 'rb') as f:
    ct_data = f.read()

ct_size = (n + 1) * np.dtype(np.uint16).itemsize
num_bits = len(ct_data) // ct_size

print(f"[*] Number of encrypted bits: {num_bits}")
print(f"[*] Expected message length: {num_bits // 8} bytes")

def gf2_solve(M, b):
    """
    Solve Mx = b over GF(2) using Gaussian elimination with full pivoting.
    M is n x n, b is n x 1.
    """
    n = len(b)
    # Create augmented matrix [M | b]
    aug = np.hstack([M.copy(), b.reshape(-1, 1)]).astype(np.uint8) % 2
    
    # Track column permutations for back-substitution
    col_order = list(range(n))
    
    for i in range(n):
        # Find pivot (search in remaining submatrix)
        pivot_found = False
        for pi in range(i, n):
            for pj in range(i, n):
                if aug[pi, pj] == 1:
                    # Swap rows i and pi
                    aug[[i, pi]] = aug[[pi, i]]
                    # Swap columns i and pj
                    aug[:, [i, pj]] = aug[:, [pj, i]]
                    col_order[i], col_order[pj] = col_order[pj], col_order[i]
                    pivot_found = True
                    break
            if pivot_found:
                break
        
        if not pivot_found:
            print(f"[!] Matrix not full rank at step {i}")
            continue
        
        # Eliminate column i in all other rows
        for j in range(n):
            if j != i and aug[j, i] == 1:
                aug[j] = (aug[j] ^ aug[i])  # XOR for GF(2)
    
    # Extract solution (reorder according to column permutations)
    x_permuted = aug[:, n]
    x = np.zeros(n, dtype=np.uint8)
    for i in range(n):
        x[col_order[i]] = x_permuted[i]
    
    return x

print("[*] Recovering secret key mod 2...")

# We need to solve: s @ A = pk (mod 2)
# Equivalently: A.T @ s.T = pk.T (mod 2)
A_mod2 = (A % 2).astype(np.uint8)
pk_mod2 = (pk % 2).astype(np.uint8)

print("[*] Solving linear system over GF(2)...")
s_mod2 = gf2_solve(A_mod2.T, pk_mod2)

# Verify solution
verification = (s_mod2 @ A_mod2) % 2
match_count = np.sum(verification == pk_mod2)
print(f"[*] Verification: {match_count}/{n} entries match")

if match_count != n:
    print("[!] Solution verification failed, trying alternative approach...")
    # Try solving A @ s = pk instead (in case matrix multiplication order is different)
    s_mod2 = gf2_solve(A_mod2, pk_mod2)
    verification = (A_mod2 @ s_mod2) % 2
    match_count = np.sum(verification == pk_mod2)
    print(f"[*] Alternative verification: {match_count}/{n} entries match")

print("[*] Decrypting message...")

# Construct the secret key for decryption
# We need sk = [-s, 1] but only care about result mod 2
# -s mod 2 = s mod 2 (since -1 ≡ 1 mod 2)
# But in uint16: -0 = 0, -1 = 65535 ≡ 1 (mod 2)
# So for mod 2 purposes: -s mod 2 = s mod 2

s_for_decrypt = s_mod2.astype(np.uint16)
sk = np.append((-s_for_decrypt) % 2, 1).astype(np.uint64)

bits = []
for i in range(num_bits):
    c = np.frombuffer(ct_data[i*ct_size:(i+1)*ct_size], dtype=np.uint16).astype(np.uint64)
    # Only need the LSB of the dot product
    # c = [A @ e, pk @ e + b]
    # sk · c = (-s) · (A @ e) + pk @ e + b
    # We compute this mod 2
    result = int(np.sum(sk * c)) & 1
    bits.append(result)

flag_bytes = Bin(bits).bytes
print(f"[+] Decrypted flag (raw): {flag_bytes}")

try:
    print(f"[+] Flag: {flag_bytes.decode('utf-8')}")
except:
    try:
        cleaned = flag_bytes.replace(b'\x00', b'').replace(b'\xff\xfe', b'').strip()
        print(f"[+] Flag (cleaned): {cleaned.decode('utf-8', errors='ignore')}")
    except:
        print(f"[+] Flag (latin-1): {flag_bytes.decode('latin-1')}")
