#!/usr/bin/env python3
"""
Paillier Cryptosystem CTF Solver
================================
Vulnerability: λ = gcd(p-1,q-1) instead of lcm(p-1,q-1)
This breaks decryption due to the random factor r^n not canceling out.

Solution: Remove r^n from enc(flag) before decrypting!
- Get enc(known) = (1 + known·n) · r^n mod n²
- Compute r^n = enc(known) · inv(1 + known·n) mod n²  
- Compute clean = enc(flag) · inv(r^n) mod n²
- Decrypt clean → flag!
"""

from pwn import *
from Crypto.Util.number import long_to_bytes

# ============== CONFIGURATION ==============
HOST = "host3.dreamhack.games"  # Change to challenge host
PORT = 20681                      # Change to challenge port
# ===========================================

def solve():
    r = remote(HOST, PORT)
    
    # Parse n
    line = r.recvline().decode().strip()
    n = int(line.split(" = ")[1])
    print(f"[+] n = {n}")
    
    # Parse e (red herring)
    r.recvline()
    
    # Parse enc(flag)
    line = r.recvline().decode().strip()
    enc_flag = int(line.split(" = ")[1])
    print(f"[+] enc(flag) = {enc_flag}")
    
    n2 = n * n
    
    # Step 1: Send known message 'A' (0x41 = 65) to get enc(65)
    known_m = 65  # ord('A')
    r.recvuntil(b"> ")
    r.sendline(b"A")
    enc_known = int(r.recvline().decode().strip())
    print(f"[+] enc(65) = {enc_known}")
    
    # Step 2: Compute r^n from enc(known)
    # enc(known) = (1 + known·n) · r^n mod n²
    # r^n = enc(known) · (1 + known·n)^(-1) mod n²
    gm_known = (1 + known_m * n) % n2
    gm_known_inv = pow(gm_known, -1, n2)
    rn = (enc_known * gm_known_inv) % n2
    print(f"[+] Extracted r^n")
    
    # Step 3: Remove r^n from enc(flag)
    # clean_flag = enc(flag) · (r^n)^(-1) = (1 + flag·n) mod n²
    rn_inv = pow(rn, -1, n2)
    clean_enc_flag = (enc_flag * rn_inv) % n2
    print(f"[+] Cleaned enc(flag) = (1 + flag·n) mod n²")
    
    # Step 4: Send clean ciphertext to decrypt oracle
    r.recvuntil(b"> ")
    r.sendline(str(clean_enc_flag).encode())
    flag_int = int(r.recvline().decode().strip())
    print(f"[+] Decrypted flag (int) = {flag_int}")
    
    # Step 5: Convert to bytes
    flag = long_to_bytes(flag_int)
    print(f"\n[🚩] FLAG: {flag.decode()}")
    
    r.close()
    return flag

if __name__ == "__main__":
    context.log_level = 'warn'
    
    print("=" * 60)
    print("Paillier Cryptosystem - Remove r^n Attack")
    print("=" * 60 + "\n")
    
    try:
        flag = solve()
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()