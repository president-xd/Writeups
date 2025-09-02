#!/usr/bin/env python3
# recover_flag.py
import re
import ast
from math import gcd
from hashlib import sha256

def parse_out_txt(path):
    with open(path, 'r', encoding='utf-8') as f:
        txt = f.read()

    # Find integers like "n = 1234"
    def find_int(name):
        m = re.search(rf'^{name}\s*=\s*([0-9]+)\s*$',
                      txt, flags=re.MULTILINE)
        if not m:
            raise ValueError(f"Could not find {name} in {path}")
        return int(m.group(1))

    n = find_int('n')
    e = find_int('e')
    c = find_int('c')
    s1 = find_int('s1')
    s2 = find_int('s2')

    # msg line: e.g. msg = b'an arbitrary message'
    m = re.search(r"^msg\s*=\s*(.+)\s*$", txt, flags=re.MULTILINE)
    if not m:
        raise ValueError("Could not find 'msg' line in out.txt")
    msg_literal = m.group(1).strip()

    # Safely evaluate the Python literal (bytes or string)
    try:
        msg_obj = ast.literal_eval(msg_literal)
    except Exception as exc:
        raise ValueError(f"Failed to parse msg literal: {msg_literal!r}: {exc}")

    # Normalize to bytes
    if isinstance(msg_obj, str):
        msg = msg_obj.encode()
    elif isinstance(msg_obj, (bytes, bytearray)):
        msg = bytes(msg_obj)
    else:
        raise ValueError(f"Parsed msg is not bytes/str: {type(msg_obj)}")

    return n, e, c, msg, s1, s2

def modinv(a, m):
    # Python 3.8+ supports pow(a, -1, m)
    try:
        return pow(a, -1, m)
    except ValueError:
        # fallback to extended gcd
        a0, m0 = a, m
        x0, x1 = 1, 0
        while m0:
            q, a0, m0 = a0 // m0, m0, a0 - (a0 // m0) * m0
            x0, x1 = x1, x0 - q * x1
        if a0 != 1:
            raise ValueError("modular inverse does not exist")
        return x0 % m

def recover(n, e, c, msg, s1, s2, verbose=True):
    h = int.from_bytes(sha256(msg).digest(), 'big')
    if verbose:
        print("Computed h = SHA256(msg) ->", h)

    # preferred: use pow(s1,e,n) then subtract h % n
    a1 = (pow(s1, e, n) - (h % n)) % n
    g1 = gcd(a1, n)
    a2 = (pow(s2, e, n) - (h % n)) % n
    g2 = gcd(a2, n)

    if verbose:
        print("gcd from s1:", g1)
        print("gcd from s2:", g2)

    p = None
    if 1 < g1 < n:
        p = g1
    elif 1 < g2 < n:
        p = g2
    else:
        # fallback: try without mod reduction (very unlikely needed)
        g1b = gcd(pow(s1, e, n) - h, n)
        g2b = gcd(pow(s2, e, n) - h, n)
        if verbose:
            print("fallback gcd(s1^e - h, n):", g1b)
            print("fallback gcd(s2^e - h, n):", g2b)
        if 1 < g1b < n:
            p = g1b
        elif 1 < g2b < n:
            p = g2b

    if not p:
        raise RuntimeError("Failed to recover factor p from s1/s2. Check out.txt correctness.")

    q = n // p
    if p * q != n:
        raise RuntimeError("Recovered factors do not multiply to n. Something's wrong.")

    if verbose:
        print("Recovered primes p and q.")
        print("p =", p)
        print("q =", q)

    # compute d using lcm or phi
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    if verbose:
        print("Computed d (private exponent).")

    # decrypt
    m = pow(c, d, n)
    # convert to bytes
    m_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')
    return m_bytes

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 recover_flag.py out.txt")
        sys.exit(1)
    path = sys.argv[1]
    n, e, c, msg, s1, s2 = parse_out_txt(path)
    try:
        flag = recover(n, e, c, msg, s1, s2, verbose=True)
    except Exception as exc:
        print("Error during recovery:", exc)
        raise
    print("\nRecovered plaintext bytes (raw):")
    print(flag)
    try:
        print("\nRecovered plaintext (utf-8):")
        print(flag.decode('utf-8', errors='replace'))
    except Exception:
        pass
