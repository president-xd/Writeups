#!/usr/bin/env python3
"""
BlackHat MEA CTF 2025 Quals :: Hatagawa II

This models each Kawa.Get() return as S[i]. For each [S]tay:
  sample k uses S[3k], S[3k+1] and burns S[3k+2].

Plaintext-invariance across samples:
  For each block b, for all samples k,
    topBytes(S[3k+b] XOR C[k,b]) == topBytes(S[b] XOR C[0,b])

Where C[k,b] is the ciphertext block aligned to the TOP bits of a 64-bit word.
"""

import sys
import re
from math import ceil
from typing import List, Tuple

from pwn import remote
from z3 import Solver, BitVec, BitVecVal, Extract, sat

W = 64
MASK64 = (1 << 64) - 1

# ---------------- I/O helpers ----------------

def parse_flag_block(text: bytes) -> Tuple[str, bytes]:
    m = re.search(rb'([^\s{}]+)\{([0-9a-f]+)\}', text)
    if not m:
        m2 = re.search(rb'\{([0-9a-f]+)\}', text)
        if not m2:
            raise ValueError("Could not find {hex} in response.")
        prefix = "BHFlagY"
        hex_payload = m2.group(1).decode()
    else:
        prefix = m.group(1).decode()
        hex_payload = m.group(2).decode()
    return prefix, bytes.fromhex(hex_payload)

def collect_ciphertexts(host: str, port: int, num_samples: int) -> Tuple[str, List[bytes]]:
    r = remote(host, port)
    r.recvuntil(b'> ')
    cblocks = []
    prefix_seen = None
    for _ in range(num_samples):
        r.sendline(b'S')
        chunk = r.recvuntil(b'|  > ', drop=False)
        pref, cbytes = parse_flag_block(chunk)
        if prefix_seen is None:
            prefix_seen = pref
        cblocks.append(cbytes)
    r.sendline(b'W')
    try:
        r.recv(timeout=0.2)
    except Exception:
        pass
    r.close()
    return prefix_seen, cblocks

# ---------------- Z3 construction ----------------

def split_blocks(cblocks: List[bytes]):
    N = len(cblocks[0])
    if any(len(cb) != N for cb in cblocks):
        raise ValueError("Inconsistent ciphertext lengths.")
    B = ceil(N / 8)
    last_len = N - 8*(B-1) if B > 0 else 0

    obs_blocks = []
    for cb in cblocks:
        blocks = []
        off = 0
        for b in range(B):
            L = 8 if b < B-1 else last_len
            blocks.append(cb[off:off+L])
            off += L
        obs_blocks.append(blocks)
    return N, B, last_len, obs_blocks

def top_aligned_u64(block_bytes: bytes) -> int:
    """Place these bytes at the TOP of a 64-bit word (big-endian block)."""
    L = len(block_bytes)
    v = int.from_bytes(block_bytes, 'big')
    shift = 8 * (8 - L)
    return (v << shift) & MASK64

def solve(cblocks: List[bytes]):
    T = len(cblocks)
    N, B, last_len, obs = split_blocks(cblocks)

    # Total emitted states across T presses: 3 per press.
    total_states = 3 * T

    s = Solver()
    a = BitVec('a', W)
    c = BitVec('c', W)
    S = [BitVec(f's_{i}', W) for i in range(total_states)]

    # Parameter shape: a ≡ 5 (mod 8); c odd
    s.add((a & 7) == 5)
    s.add((c & 1) == 1)

    # LCG transitions across all emitted states
    for i in range(total_states - 1):
        s.add(S[i+1] == a * S[i] + c)  # modulo 2^64 via bit-vector wrap

    # Plaintext invariance across samples:
    # For block b, top bytes of (S[3k+b] XOR C[k,b]) equal those of (S[b] XOR C[0,b]).
    for b in range(B):
        L = 8 if b < B-1 else last_len
        top_hi = 63
        top_lo = 64 - 8*L

        C0b = BitVecVal(top_aligned_u64(obs[0][b]), W)
        for k in range(T):
            Ckb = BitVecVal(top_aligned_u64(obs[k][b]), W)
            left  = S[3*k + b] ^ Ckb
            right = S[b]       ^ C0b
            if L == 8:
                s.add(left == right)
            else:
                s.add(Extract(top_hi, top_lo, left) == Extract(top_hi, top_lo, right))

    if s.check() != sat:
        return None

    m = s.model()
    a_val = m[a].as_long() & MASK64
    c_val = m[c].as_long() & MASK64

    # Recover plaintext bytes from the base sample k=0
    plain = bytearray()
    for b in range(B):
        L = 8 if b < B-1 else last_len
        Sb  = (m[S[b]].as_long() & MASK64)
        C0b = top_aligned_u64(obs[0][b])
        Pb64 = Sb ^ C0b
        pb = Pb64.to_bytes(8, 'big')[:L]  # take TOP L bytes
        plain += pb

    return a_val, c_val, bytes(plain)

# ---------------- main ----------------

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "34.252.33.37"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 32303
    samples = int(sys.argv[3]) if len(sys.argv) > 3 else 8

    print(f"[*] Connecting to {host}:{port} and collecting {samples} samples...")
    prefix, cblocks = collect_ciphertexts(host, port, samples)
    print(f"[*] Prefix detected: {prefix}")
    print(f"[*] Ciphertext length: {len(cblocks[0])} bytes ({len(cblocks[0])*2} hex chars)")

    res = solve(cblocks)
    if res is None:
        print("[!] UNSAT. Try increasing samples (e.g., 10–12).")
        sys.exit(2)

    a_val, c_val, plain = res
    true_flag = f"{prefix}{{{plain.hex()}}}"
    print(f"[+] a = 0x{a_val:016x}, c = 0x{c_val:016x}")
    print(f"[+] True flag recovered:\n{true_flag}")

if __name__ == "_main__":
    main()