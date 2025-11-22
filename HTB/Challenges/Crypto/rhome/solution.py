#!/usr/bin/env python3
from pwn import remote
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import sys
from math import isqrt


# ---------------------- BSGS discrete log ---------------------- #
def dlog_bsgs(g, h, p, N):
    """
    Solve for x in h = g^x mod p, with 0 <= x < N using Baby-Step Giant-Step.
    N should be an upper bound on the order of g (here ~2^42).
    """
    m = isqrt(N) + 1

    # Baby steps: g^j for j in [0, m)
    table = {}
    cur = 1
    for j in range(m):
        if cur not in table:  # keep the first index if collisions
            table[cur] = j
        cur = (cur * g) % p

    # factor = g^{-m} mod p
    gm = pow(g, m, p)
    inv_gm = pow(gm, p - 2, p)  # since p is prime

    # Giant steps: h * g^{-im}
    gamma = h
    for i in range(m + 1):
        if gamma in table:
            return i * m + table[gamma]
        gamma = (gamma * inv_gm) % p

    raise ValueError("Discrete log not found within bound N")


# ---------------------- Menu interaction helpers ---------------------- #
def get_params(io):
    """
    Sends option 1, parses p, g, A, B.
    """
    # Read menu until '>' prompt
    io.recvuntil(b"> ")
    io.sendline(b"1")

    p = g = A = B = None
    for _ in range(4):
        line = io.recvline().decode().strip()
        if line.startswith("p ="):
            p = int(line.split("=")[1])
        elif line.startswith("g ="):
            g = int(line.split("=")[1])
        elif line.startswith("A ="):
            A = int(line.split("=")[1])
        elif line.startswith("B ="):
            B = int(line.split("=")[1])

    if None in (p, g, A, B):
        raise ValueError("Failed to parse parameters")

    return p, g, A, B


def get_encrypted_flag(io):
    """
    Sends option 3, returns ciphertext bytes.
    """
    io.recvuntil(b"> ")
    io.sendline(b"3")
    line = io.recvline().decode().strip()
    # Expected: "encrypted = <hex>"
    ct_hex = line.split("=")[1].strip()
    return bytes.fromhex(ct_hex)


# ---------------------- Main exploit ---------------------- #
def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <host> <port>")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])

    io = remote(host, port)

    # 1. Get DH parameters
    p, g, A, B = get_params(io)
    print("[+] Got parameters")
    print(f"p = {p}")
    print(f"g = {g}")
    print(f"A = {A}")
    print(f"B = {B}")

    # 2. Solve discrete log A = g^a mod p
    print("[+] Solving discrete log a such that A = g^a mod p ...")
    # subgroup order q is ~ 2^42, so use upper bound 2^42
    N = 1 << 42
    a = dlog_bsgs(g, A, p, N)
    print(f"[+] Found a = {a}")

    # 3. Compute shared secret ss = B^a mod p
    ss = pow(B, a, p)
    print(f"[+] Shared secret ss = {ss}")

    # 4. Derive AES key
    from hashlib import sha256
    key = sha256(long_to_bytes(ss)).digest()[:16]
    print(f"[+] AES key = {key.hex()}")

    # 5. Get encrypted flag
    ct = get_encrypted_flag(io)
    print(f"[+] Ciphertext = {ct.hex()}")

    # 6. Decrypt
    cipher = AES.new(key, AES.MODE_ECB)
    pt_padded = cipher.decrypt(ct)
    flag = unpad(pt_padded, 16)

    print(f"[+] Flag: {flag}")
    try:
        print(f"[+] Flag (utf-8): {flag.decode()}")
    except UnicodeDecodeError:
        pass

    io.close()


if __name__ == "__main__":
    main()
