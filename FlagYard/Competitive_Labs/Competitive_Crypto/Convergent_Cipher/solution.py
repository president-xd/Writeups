#!/usr/bin/env python3
import socket, sys, re, hashlib, multiprocessing as mp
from typing import List, Tuple

HOST = sys.argv[1] if len(sys.argv) > 1 else "34.252.33.37"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 31142
TIMEOUT = 12.0

MOD = (1 << 24) + 43
MASK24 = (1 << 24) - 1

def i3(b: bytes) -> int:
    return int.from_bytes(b, "big")

def b3(x: int) -> bytes:
    return (x & MASK24).to_bytes(3, "big")

def sub24(x: int) -> int:
    """Return sub(x) as 24-bit int (i.e., (x^{-1} mod MOD) % 2^24). x in [0, 2^24)."""
    if x == 0:
        # non-invertible modulo prime MOD
        return 0  # won't match anyway; safe filler
    return pow(x, -1, MOD) & MASK24

def recv_until(sock, prompt: str) -> str:
    buf = ""
    sock.settimeout(TIMEOUT)
    while prompt not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            break
        buf += chunk.decode(errors="ignore")
    return buf

def parse_hex_from_line(line: str) -> bytes:
    # Expect "Ciphertext: <hex>" or prompt lines
    m = re.search(r"Ciphertext:\s*([0-9a-fA-F]+)", line)
    if not m:
        raise ValueError("Failed parsing ciphertext")
    hx = m.group(1).strip()
    return bytes.fromhex(hx)

def worker_scan(args) -> Tuple[List[int], List[int]]:
    """
    Scan a range of even x's; for each pair (x, x^1) compute Dpair = sub(x)^sub(x^1).
    If matches D1 or D2, add both candidates for that half.
    """
    start, stop, D_first, D_second = args
    cand1 = []
    cand2 = []
    # Process pairs (x, x^1) by stepping 2
    for x in range(start, stop, 2):
        x1 = x ^ 1  # x+1
        if x == 0:
            y0 = 0
        else:
            y0 = sub24(x)
        y1 = sub24(x1)
        d = y0 ^ y1
        if d == D_first:
            cand1.extend((x, x1))
        if d == D_second:
            cand2.extend((x, x1))
    return cand1, cand2

def find_half_candidates(D_first: int, D_second: int, nprocs: int = max(2, mp.cpu_count() // 2)) -> Tuple[List[int], List[int]]:
    # split [0, 1<<24) into chunks of even starts
    total = 1 << 24
    # Ensure even boundaries
    chunks = []
    step = (total // nprocs) & ~1  # make it even
    start = 0
    for _ in range(nprocs - 1):
        chunks.append((start, start + step, D_first, D_second))
        start += step
    chunks.append((start, total, D_first, D_second))

    with mp.Pool(nprocs) as pool:
        res = pool.map(worker_scan, chunks)
    c1, c2 = [], []
    for a, b in res:
        c1.extend(a)
        c2.extend(b)
    # Dedup (pairs add both x and x^1 already)
    return sorted(set(c1)), sorted(set(c2))

def try_keys_and_submit(sock, pt1: bytes, pt2: bytes, ct1: bytes, ct2: bytes, k0_cands: List[int], k1_cands: List[int]) -> bool:
    # Try all combinations (usually very small), verify via SHA256 first 6 bytes and exact encryption.
    for k0 in k0_cands:
        for k1 in k1_cands:
            key = b3(k0) + b3(k1)
            k2 = hashlib.sha256(key).digest()[:6]

            # recompute expected CTs and check
            def enc_once(pt: bytes) -> bytes:
                u1 = i3(pt[:3]) ^ k0
                u2 = i3(pt[3:]) ^ k1
                v1 = b3(sub24(u1))
                v2 = b3(sub24(u2))
                return bytes([a ^ b for a, b in zip(v1 + v2, k2)])

            if enc_once(pt1) == ct1 and enc_once(pt2) == ct2:
                # submit key
                sock.sendall((key.hex() + "\n").encode())
                tail = sock.recv(65536).decode(errors="ignore")
                print(tail.strip())
                return True
    return False

def main():
    # 1) Connect and get two ciphertexts quickly
    s = socket.create_connection((HOST, PORT), timeout=TIMEOUT)

    # First prompt
    banner = recv_until(s, "Plaintext (hex): ")
    # Query 1: A||C = 000000||000000
    pt1 = bytes.fromhex("000000000000")
    s.sendall((pt1.hex() + "\n").encode())
    out1 = recv_until(s, "Plaintext (hex): ")  # includes the "Ciphertext: ..." line
    # Parse ct1
    lines = out1.strip().splitlines()
    ct1 = None
    for line in lines[::-1]:
        if "Ciphertext:" in line:
            ct1 = parse_hex_from_line(line)
            break
    if ct1 is None or len(ct1) != 6:
        raise RuntimeError("Couldn't parse ct1")

    # Query 2: flip LSB in each half → 000001000001
    pt2 = bytes.fromhex("000001000001")
    s.sendall((pt2.hex() + "\n").encode())
    out2 = recv_until(s, "Key (hex): ")
    # Parse ct2
    lines = out2.strip().splitlines()
    ct2 = None
    for line in lines[::-1]:
        if "Ciphertext:" in line:
            ct2 = parse_hex_from_line(line)
            break
    if ct2 is None or len(ct2) != 6:
        raise RuntimeError("Couldn't parse ct2")

    # 2) Compute per-half XOR diffs (k2 cancels)
    D_first  = i3(ct1[:3]) ^ i3(ct2[:3])
    D_second = i3(ct1[3:]) ^ i3(ct2[3:])

    # 3) Find candidate half-keys in parallel
    k0_cands, k1_cands = find_half_candidates(D_first, D_second)

    if not k0_cands or not k1_cands:
        print("[!] No candidates found for one of the halves — try re-running (new key) or use more CPU cores.")
        s.close()
        return

    # 4) Combine, verify, and submit
    ok = try_keys_and_submit(s, pt1, pt2, ct1, ct2, k0_cands, k1_cands)
    if not ok:
        print("[!] No candidate key verified; collision or unlucky mapping. Re-run to get a new instance/key.")
    s.close()

if __name__ == "__main__":
    main()
