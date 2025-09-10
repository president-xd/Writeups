#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# BlackHat MEA CTF 2025 Quals :: Hatagawa I - Final, robust solver
#
# Does NOT rely on fragile n-th roots. It:
#  - Grabs many ciphertext slices in ONE TCP session.
#  - Uses the known 8-byte prefix to recover the start-of-slice LCG states z_i.
#  - Recovers the step-n multiplier A from multiple triples and intersects candidates.
#  - Lifts ALL a such that a^n ≡ A (mod 2^64), enforcing a ≡ 5 (mod 8).
#  - Recovers c (odd) from z_{i+1} = A*z_i + c*S, checks consistency across pairs.
#  - Decrypts and prints the flag.

import re
import socket
import sys
from typing import List, Set

HOST_DEFAULT = "34.252.33.37"
PORT_DEFAULT = 30706
TAKE_SLICES = 14  # grab plenty of consecutive slices in one session
DEFAULT_PREFIX = b"BHFlagY{"  # 8-byte known prefix from challenge

MASK64 = (1 << 64) - 1
HEX_RE = re.compile(rb"\b([0-9a-f]{32,})\b", re.I)

# -------------------- small helpers --------------------

def tz(x: int) -> int:
    if x == 0:
        return 64
    return (x & -x).bit_length() - 1

def inv_odd_mod_2k(a: int, k: int) -> int:
    assert a & 1
    x = 1
    for i in range(1, k):
        mod = 1 << (i + 1)
        x = (x * (2 - (a * x) % mod)) % mod
    return x % (1 << k)

def u64(b: bytes) -> int:
    return int.from_bytes(b, "big")

def p64(x: int) -> bytes:
    return (x & MASK64).to_bytes(8, "big")

def geom_sum_mod(a: int, n: int, M: int) -> int:
    s, term = 0, 1 % M
    for _ in range(n):
        s = (s + term) % M
        term = (term * a) % M
    return s

# -------------------- I/O with server --------------------

def recv_until(sock: socket.socket, needle: bytes, max_bytes: int = 1_000_000) -> bytes:
    buf = bytearray()
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        if needle in buf or len(buf) >= max_bytes:
            break
    return bytes(buf)

def get_ciphertexts(host: str, port: int, count: int) -> List[bytes]:
    s = socket.create_connection((host, port))
    recv_until(s, b"Menu:")
    ctexts = []
    for _ in range(count):
        s.sendall(b"S\n")
        data = recv_until(s, b"Menu:")
        m_all = HEX_RE.findall(data)
        if not m_all:
            s.sendall(b"W\n")
            s.close()
            raise RuntimeError("No ciphertext hex found in server output.")
        hex_blob = max(m_all, key=len)
        ctexts.append(bytes.fromhex(hex_blob.decode()))
    s.sendall(b"W\n")
    s.close()
    return ctexts

# -------------------- core recovery --------------------

def recover_stepn_A_candidates(z0: int, z1: int, z2: int) -> Set[int]:
    """Return all 64-bit A candidates from z0->z1->z2 under modulus 2^64."""
    d1 = (z1 - z0) & MASK64
    d2 = (z2 - z1) & MASK64
    if d1 == 0 or d2 == 0:
        return set()
    v = min(tz(d1), tz(d2))
    k = 64 - v
    d1p = d1 >> v
    d2p = d2 >> v
    inv = inv_odd_mod_2k(d1p, k)
    A_mod = (d2p * inv) % (1 << k)
    return { (A_mod + (t << k)) & MASK64 for t in range(1 << v) }

def lift_all_a_from_A(A: int, n: int) -> Set[int]:
    """
    All a (64-bit) such that a^n == A (mod 2^64), with a ≡ 5 (mod 8).
    Lift bit-by-bit: keep the extensions that match pow(a,n,M) at each M=2^(t+1).
    """
    cands = {5}  # per challenge MUL = (..<<3)|5 => a ≡ 5 (mod 8)
    for t in range(3, 64):
        M = 1 << (t + 1)
        tgt = A & (M - 1)
        new = set()
        for a in cands:
            a0 = a % M
            # next bit can be 0 or 1
            for bit in (0, 1):
                a_try = (a0 + (bit << t)) % M
                if pow(a_try, n, M) == tgt:
                    new.add(a_try)
        if not new:
            return set()
        cands = new
    return cands  # full 64-bit values

def recover_c_lifts(a: int, z0: int, z1: int, n: int) -> List[int]:
    """All odd 64-bit c consistent with z1 = a^n*z0 + c*S (mod 2^64)."""
    M = 1 << 64
    A = pow(a, n, M)
    S = geom_sum_mod(a, n, M)
    vS = tz(S)
    B = (z1 - (A * z0) % M) % M
    if vS > 0 and (B & ((1 << vS) - 1)) != 0:
        return []
    k = 64 - vS
    if k == 0:
        return []
    S_red = (S >> vS) % (1 << k)
    if (S_red & 1) == 0:
        return []  # should be odd after removing all 2s
    invS = inv_odd_mod_2k(S_red, k)
    c_base = ((B >> vS) * invS) % (1 << k)
    cands = []
    for t in range(1 << vS):
        c = (c_base + (t << k)) & MASK64
        if c & 1:  # ADD was chosen odd
            cands.append(c)
    return cands

def stepn_from_z(z: int, a: int, c: int, n: int) -> int:
    """Compute z' = A*z + c*S (mod 2^64) using fast pow/sum."""
    M = 1 << 64
    A = pow(a, n, M)
    S = geom_sum_mod(a, n, M)
    return (A * z + (c * S) % M) & MASK64

def decrypt_first_slice(ct: bytes, a: int, c: int, z0: int) -> bytes:
    L = len(ct)
    n = (L + 7) // 8
    s = z0
    otp = bytearray()
    for _ in range(n):
        otp += p64(s)
        s = (a * s + c) & MASK64
    return bytes(ci ^ oi for ci, oi in zip(ct, otp[:L]))

def solve_instance(host: str, port: int, count: int, prefix: bytes):
    if len(prefix) != 8:
        raise RuntimeError("Flag prefix must be exactly 8 bytes (e.g., BHFlagY{).")

    ctexts = get_ciphertexts(host, port, count=count)
    L = len(ctexts[0])
    n = (L + 7) // 8

    # Recover start-of-slice states z_i from first 8 bytes using known prefix.
    z = [ u64(bytes(ci ^ pi for ci, pi in zip(ct[:8], prefix))) for ct in ctexts ]
    if len(z) < 3:
        raise RuntimeError("Need at least 3 slices to solve.")

    # Intersect A candidates from multiple triples to prune hard.
    A_set = None
    triples = min(len(z) - 2, 6)  # use up to 6 triples
    for i in range(triples):
        Ai = recover_stepn_A_candidates(z[i], z[i+1], z[i+2])
        if not Ai:
            continue
        A_set = Ai if A_set is None else (A_set & Ai)
        if A_set and len(A_set) == 1:
            break
    if not A_set:
        raise RuntimeError("Failed to recover step-n multiplier A.")

    # Try each A, lift all 'a', solve 'c', verify across all pairs, decrypt.
    for A in A_set:
        a_candidates = lift_all_a_from_A(A, n)
        for a in a_candidates:
            # c must be consistent across ALL pairs modulo 2^(64 - v2(S))
            M = 1 << 64
            S = geom_sum_mod(a, n, M)
            vS = tz(S)
            k = 64 - vS
            if k == 0:
                continue
            S_red = (S >> vS) % (1 << k)
            if (S_red & 1) == 0:
                continue
            invS = inv_odd_mod_2k(S_red, k)
            Achk = pow(a, n, M)

            # derive c_hat from each pair and require equality
            c_hat = None
            consistent = True
            for i in range(len(z) - 1):
                B = ((z[i+1] - (Achk * z[i]) % M) % M)
                if vS > 0 and (B & ((1 << vS) - 1)) != 0:
                    consistent = False
                    break
                cur = ((B >> vS) * invS) % (1 << k)
                if c_hat is None:
                    c_hat = cur
                elif cur != c_hat:
                    consistent = False
                    break
            if not consistent:
                continue
            if k >= 1 and (c_hat & 1) == 0:
                continue  # c must be odd

            # enumerate the vS lifts of c and fully verify transitions
            c_cands = [ ((c_hat + (t << k)) & MASK64) for t in range(1 << vS) if ((c_hat + (t << k)) & 1) ]
            for c in c_cands:
                ok = True
                for i in range(len(z) - 1):
                    if stepn_from_z(z[i], a, c, n) != z[i+1]:
                        ok = False
                        break
                if not ok:
                    continue

                pt = decrypt_first_slice(ctexts[0], a, c, z[0])
                if pt.startswith(prefix) and pt.endswith(b"}"):
                    print(pt.decode(errors="replace"))
                    return
                # relaxed: brace could be inside later
                if pt.startswith(prefix) and b"}" in pt:
                    print(pt.decode(errors="replace"))
                    return

    raise RuntimeError("Parameters found, but no candidate produced a valid-looking flag. "
                       "Try increasing TAKE_SLICES or confirm the 8-byte prefix.")

# -------------------- entry --------------------

if __name__ == "__main__":
    host = HOST_DEFAULT
    port = PORT_DEFAULT
    if len(sys.argv) >= 3:
        host = sys.argv[1]
        port = int(sys.argv[2])
    prefix = DEFAULT_PREFIX
    if len(sys.argv) >= 4:
        prefix = sys.argv[3].encode()

    try:
        solve_instance(host, port, TAKE_SLICES, prefix)
    except Exception as e:
        print(f"[!] {e}")
        sys.exit(1)
