from pwn import *
from Crypto.Util.number import inverse, long_to_bytes
from gmpy2 import isqrt

# Connect to the challenge
r = remote('host8.dreamhack.games', 13041)
# r = process(['python', 'prob.py'])  # For local testing

e = 65537

def factor_with_hint(n, h):
    """
    Given n = p*q and h = p - q (p > q), solve for p and q.
    
    p = q + h
    n = q * (q + h) = q^2 + h*q
    q^2 + h*q - n = 0
    q = (-h + sqrt(h^2 + 4n)) / 2
    """
    discriminant = h * h + 4 * n
    sqrt_disc = isqrt(discriminant)
    q = (-h + sqrt_disc) // 2
    p = q + h
    assert p * q == n, "Factorization failed!"
    return p, q

# Store all keys for flag decryption
keys = []

# Wait for generation
r.recvuntil(b"Okay, Let's go!")
print("[*] Server ready, starting solve...")

for step in range(1, 11):
    # Parse the output
    r.recvuntil(b'step ')
    r.recvline()  # step number
    r.recvline()  # e = ...
    n_line = r.recvline().decode()
    c_line = r.recvline().decode()
    h_line = r.recvline().decode()
    
    n = int(n_line.split('=')[1].strip())
    c = int(c_line.split('=')[1].strip())
    h = int(h_line.split('=')[1].strip())
    
    # Factor n using the hint h = p - q
    p, q = factor_with_hint(n, h)
    
    # Store for later flag decryption
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    keys.append((n, d))
    
    # Decrypt message
    m = pow(c, d, n)
    
    # Send answer
    r.sendlineafter(b'> ', str(m).encode())
    print(f"[+] Step {step} done")

# Get encrypted flag
enc_flag = int(r.recvline().decode().strip())
print(f"[*] Encrypted flag received")

# Decrypt flag - try all 10 n values (flag was encrypted with random one)
for i, (n, d) in enumerate(keys):
    try:
        flag_int = pow(enc_flag, d, n)
        flag = long_to_bytes(flag_int)
        if b'DH{' in flag:
            print(f"[*] Flag (using key {i+1}): {flag.decode()}")
            break
    except:
        continue
else:
    # Print all attempts if DH{ not found
    for i, (n, d) in enumerate(keys):
        flag_int = pow(enc_flag, d, n)
        flag = long_to_bytes(flag_int)
        print(f"[?] Key {i+1}: {flag}")
