#!/usr/bin/env python3
"""
Broken Decryptor — CTF Solution
================================
Vulnerability:
  - decrypt() is broken (calls .encode() on bytes → AttributeError)
  - encrypt() uses AES-CTR with a FIXED key/IV (same keystream every call)
    and XORs the AES-CTR output with a random OTP whose bytes are never 0

Attack (Coupon Collector):
  Since OTP bytes ∈ {1..255} (never 0), for any fixed plaintext P:
    encrypt(P)[i] = P[i] ⊕ K[i] ⊕ OTP[i]
  The value P[i] ⊕ K[i] can NEVER appear at position i.

  1. Encrypt zeros many times → the never-appearing value = K[i] (keystream)
  2. Get encrypted flag many times, XOR with K → the never-appearing value = flag[i]
"""

from pwn import *
import sys


def solve(host, port):
    r = remote(host, port)

    def get_flag_ct():
        """Request encrypted flag (option 1)."""
        r.recvuntil(b'option: ')
        r.sendline(b'1')
        return bytes.fromhex(r.recvline().strip().decode())

    def encrypt_zeros(length):
        """Encrypt all-zero plaintext (option 2)."""
        r.recvuntil(b'option: ')
        r.sendline(b'2')
        r.recvuntil(b'plaintext: ')
        r.sendline(('00' * length).encode())
        return bytes.fromhex(r.recvline().strip().decode())

    # ── Step 1: Determine flag length ──────────────────────────────────
    flag_ct = get_flag_ct()
    flag_len = len(flag_ct)
    log.info(f"Flag length: {flag_len} bytes")

    MAX_SAMPLES = 4000
    CHECK_EVERY = 250

    # ── Step 2: Recover AES-CTR keystream ──────────────────────────────
    # encrypt(0x00 * L) = keystream ⊕ OTP
    # OTP[i] ≠ 0  ⟹  keystream[i] never appears at position i
    log.info("Stage 1: Recovering keystream (encrypting zeros)...")
    seen_k = [set() for _ in range(flag_len)]

    for i in range(MAX_SAMPLES):
        ct = encrypt_zeros(flag_len)
        for j in range(flag_len):
            seen_k[j].add(ct[j])

        if (i + 1) % CHECK_EVERY == 0:
            remaining = sum(1 for j in range(flag_len) if len(seen_k[j]) < 255)
            log.info(f"  [{i+1:>4d}] byte positions not yet solved: {remaining}")
            if remaining == 0:
                log.info(f"  Keystream fully recovered after {i+1} samples")
                break

    keystream = bytearray(flag_len)
    for j in range(flag_len):
        missing = set(range(256)) - seen_k[j]
        if len(missing) != 1:
            log.warning(f"  Position {j}: {len(missing)} candidates — need more samples")
        keystream[j] = min(missing)  # should be exactly 1

    log.info(f"Keystream: {bytes(keystream).hex()}")

    # ── Step 3: Recover flag ───────────────────────────────────────────
    # flag_ct[i] = flag[i] ⊕ K[i] ⊕ OTP[i]
    # flag_ct[i] ⊕ K[i] = flag[i] ⊕ OTP[i]
    # OTP[i] ≠ 0  ⟹  flag[i] never appears at position i
    log.info("Stage 2: Recovering flag...")
    seen_f = [set() for _ in range(flag_len)]

    # Process the flag sample we already have
    for j in range(flag_len):
        seen_f[j].add(flag_ct[j] ^ keystream[j])

    for i in range(MAX_SAMPLES):
        ct = get_flag_ct()
        for j in range(flag_len):
            seen_f[j].add(ct[j] ^ keystream[j])

        if (i + 1) % CHECK_EVERY == 0:
            remaining = sum(1 for j in range(flag_len) if len(seen_f[j]) < 255)
            log.info(f"  [{i+1:>4d}] byte positions not yet solved: {remaining}")
            if remaining == 0:
                log.info(f"  Flag fully recovered after {i+1} samples")
                break

    flag = bytearray(flag_len)
    for j in range(flag_len):
        missing = set(range(256)) - seen_f[j]
        if len(missing) != 1:
            log.warning(f"  Position {j}: {len(missing)} candidates — need more samples")
        flag[j] = min(missing)

    log.success(f"Flag: {bytes(flag).decode()}")
    r.close()
    return bytes(flag).decode()


if __name__ == '__main__':
    host = sys.argv[1] if len(sys.argv) > 1 else '154.57.164.67'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 31442
    solve(host, port)
