#!/usr/bin/env python3
"""
LA CTF - 67 Prime RSA Challenge Solver

p, q are 256-digit primes with every digit in {6,7} and last digit = 7.
Factor n via digit-by-digit BFS: extend (p_partial, q_partial) from the LSB,
pruning with (p*q) mod 10^k == n mod 10^k and product-size bounds.
"""

import socket
import base64
import struct
import re
import time
from Crypto.Util.number import long_to_bytes


def factor_67(n):
    """Factor n = p*q where p,q are 256-digit numbers with digits in {6,7}, last digit 7."""
    pow10 = [1] * 257
    for i in range(1, 257):
        pow10[i] = pow10[i - 1] * 10

    candidates = [(7, 7)]

    for k in range(1, 256):
        mod = pow10[k + 1]
        n_mod = n % mod
        step = pow10[k]
        new_candidates = []

        for p_part, q_part in candidates:
            for pd in (6, 7):
                p_new = p_part + pd * step
                for qd in (6, 7):
                    q_new = q_part + qd * step
                    if (p_new * q_new) % mod == n_mod:
                        new_candidates.append((p_new, q_new))

        if k >= 3:
            rep = (pow10[256] - pow10[k + 1]) // 9
            rem_lo = 6 * rep
            rem_hi = 7 * rep

            pruned = []
            for p_part, q_part in new_candidates:
                p_lo = p_part + rem_lo
                p_hi = p_part + rem_hi
                q_lo = q_part + rem_lo
                q_hi = q_part + rem_hi

                if p_lo * q_lo > n or p_hi * q_hi < n:
                    continue
                if p_lo > n // q_lo + 1 or p_hi < n // q_hi:
                    continue

                pruned.append((p_part, q_part))

            new_candidates = pruned

        candidates = new_candidates

        if k % 25 == 0 or k >= 250:
            print(f"  digit {k:3d}: {len(candidates)} candidates")

    for p, q in candidates:
        if p * q == n:
            return p, q
    return None, None


def solve_pow(challenge):
    """Solve redpwn proof of work in pure Python.
    
    Algorithm (from github.com/redpwn/pow):
    - mod = 2^1279 - 1 (Mersenne prime)
    - exp = 2^1277
    - Decode challenge: "s.<difficulty_b64>.<x_b64>"
    - Solve: for d iterations: x = pow(x, exp, mod); x ^= 1
    - Return: "s.<solution_b64>"
    """
    MOD = (1 << 1279) - 1
    EXP = 1 << 1277

    parts = challenge.split(".")
    assert parts[0] == "s", f"Unknown version: {parts[0]}"

    d_bytes = base64.b64decode(parts[1])
    d_bytes = b'\x00' * (4 - len(d_bytes)) + d_bytes
    d = struct.unpack(">I", d_bytes)[0]

    x = int.from_bytes(base64.b64decode(parts[2]), "big")

    print(f"PoW difficulty: {d}, solving...")
    t0 = time.time()
    for i in range(d):
        x = pow(x, EXP, MOD)
        x ^= 1
        if (i + 1) % 1000 == 0:
            elapsed = time.time() - t0
            eta = elapsed / (i + 1) * (d - i - 1)
            print(f"  iteration {i+1}/{d}, elapsed {elapsed:.1f}s, ETA {eta:.1f}s")

    solution = f"s.{base64.b64encode(x.to_bytes((x.bit_length() + 7) // 8, 'big')).decode()}"
    print(f"PoW solved in {time.time() - t0:.1f}s")
    return solution


def recv_until(s, marker, timeout=10):
    """Receive data until marker is found."""
    data = b""
    s.settimeout(timeout)
    while marker not in data:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        except socket.timeout:
            break
    return data


def recv_all(s, timeout=5):
    """Receive all available data."""
    data = b""
    s.settimeout(timeout)
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        except socket.timeout:
            break
    return data


def main():
    HOST = "chall.lac.tf"
    PORT = 31180

    print(f"Connecting to {HOST}:{PORT}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    # Receive initial data (proof of work prompt)
    initial = recv_until(s, b"solution:", timeout=10)
    text = initial.decode()
    print(f"< {text}")

    if "proof of work" in text:
        # Extract challenge string
        match = re.search(r'(s\.\S+)', text)
        if match:
            challenge = match.group(1)
        else:
            challenge = text.split()[-2]  # fallback

        solution = solve_pow(challenge)
        s.sendall(solution.encode() + b"\n")

        # Wait for response
        time.sleep(2)
        data = recv_all(s, timeout=10).decode().strip()
    else:
        data = text

    s.close()
    print(f"\nReceived:\n{data}\n")

    # Parse n and c
    lines = [l.strip() for l in data.split("\n") if "=" in l]
    n_line = [l for l in lines if l.startswith("n=") or l.startswith("n ")][0]
    c_line = [l for l in lines if l.startswith("c=") or l.startswith("c ")][0]
    n = int(n_line.split("=")[1])
    c = int(c_line.split("=")[1])

    e = 65537
    print(f"n has {len(str(n))} digits\n")

    print("Factoring n (digit-by-digit BFS)...")
    p, q = factor_67(n)

    if p is None:
        print("ERROR: Failed to factor!")
        return

    print(f"\np = {p}")
    print(f"q = {q}")
    assert p * q == n

    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    m = pow(c, d, n)
    flag = long_to_bytes(m)
    print(f"\nFlag: {flag.decode()}")


if __name__ == "__main__":
    main()
