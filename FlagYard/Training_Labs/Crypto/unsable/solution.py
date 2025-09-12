#!/usr/bin/env python3
import re, sys, socket, math, random

HOST = sys.argv[1] if len(sys.argv) > 1 else "34.252.33.37"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 31142

# ---------- math utils ----------
def is_probable_prime(n: int) -> bool:
    if n < 2:
        return False
    small = [2,3,5,7,11,13,17,19,23,29,31,37,41,43]
    for p in small:
        if n % p == 0:
            return n == p
    # Miller-Rabin
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    # Deterministic set good enough for ~128+ bits + a few randoms
    bases = [2, 325, 9375, 28178, 450775, 9780504, 1795265022]
    for a in bases + [random.randrange(2, n-2) for _ in range(5)]:
        a %= n
        if a <= 1:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n-1:
            continue
        for _ in range(s-1):
            x = (x * x) % n
            if x == n-1:
                break
        else:
            return False
    return True

def pollard_brent(n: int) -> int:
    if n % 2 == 0:
        return 2
    if is_probable_prime(n):
        return n
    while True:
        y = random.randrange(1, n-1)
        c = random.randrange(1, n-1)
        m = random.randrange(1, n-1)
        g, r, q = 1, 1, 1
        f = lambda x: (pow(x, 2, n) + c) % n
        while g == 1:
            x = y
            for _ in range(r):
                y = f(y)
            k = 0
            while k < r and g == 1:
                ys = y
                for _ in range(min(m, r - k)):
                    y = f(y)
                    q = (q * abs(x - y)) % n
                g = math.gcd(q, n)
                k += m
            r <<= 1
        if g == n:
            g = 1
            while g == 1:
                ys = f(ys)
                g = math.gcd(abs(x - ys), n)
        if g != n:
            return g

def factor(n: int, out=None):
    if out is None:
        out = []
    if n == 1:
        return out
    if is_probable_prime(n):
        out.append(n)
        return out
    d = pollard_brent(n)
    factor(d, out)
    factor(n // d, out)
    return out

def is_square(n: int) -> (bool, int):
    if n < 0:
        return (False, 0)
    x = math.isqrt(n)
    return (x * x == n, x)

def long_to_bytes(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, "big")

# ---------- solve utils ----------
def parse_numbers(blob: str):
    # Accept lines like "n1 = 123", "ct1 = 456", etc.
    nums = {}
    for key in ("n1","ct1","ct2","n2","ct3","ct4"):
        m = re.search(rf"{key}\s*=\s*([0-9]+)", blob)
        if not m:
            raise ValueError(f"Couldn't find {key}")
        nums[key] = int(m.group(1))
    return nums

def nc_get_blob(host, port, timeout=10):
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    chunks = []
    # read until socket closes or enough lines received
    try:
        while True:
            data = s.recv(65536)
            if not data:
                break
            chunks.append(data.decode())
            # heuristic: once we've seen ct4 line, we can stop
            if "ct4" in chunks[-1] or ("ct4" in "".join(chunks)):
                break
    except socket.timeout:
        pass
    s.close()
    return "".join(chunks)

def candidate_P_from_ct(ct: int):
    """
    Try to get P by factoring 'ct' as x*(x+P).
    If ct is semiprime, one pollard gives us x and ct/x; else we fully factor and try combinations.
    We'll try quick path first: one nontrivial factor -> two candidates.
    """
    # Quick path: one factor
    f = pollard_brent(ct)
    if f == ct:
        # Shouldn't happen; ct is composite as x*(x+P)
        pass
    g = ct // f
    cand = []
    # Try both orientations
    for x,y in ((min(f,g), max(f,g)), (max(f,g), min(f,g))):
        if y > x:
            P = y - x
            cand.append((x, P))
    # If both failed later, we can fall back to full factor (rare)
    return cand

def recover_x_from_ct_P(ct: int, P: int):
    # Solve x^2 + P x - ct = 0 over integers
    disc = P*P + 4*ct
    ok, r = is_square(disc)
    if not ok:
        return None
    x = (-P + r) // 2
    if x < 0:
        return None
    if x * (x + P) != ct:
        return None
    return x

def pick_key_from_masked(masked: bytes):
    # Find k in [0..125] such that unxored startswith b"FlagY{"
    for k in range(0, 126):
        plain = bytes(b ^ k for b in masked)
        if plain.startswith(b"FlagY{"):
            return k, plain
    return None, None

def main():
    blob = nc_get_blob(HOST, PORT)
    # print(blob)  # uncomment for debugging
    nums = parse_numbers(blob)
    ct1 = nums["ct1"]; ct3 = nums["ct3"]

    # Derive P candidates from ct1
    cands = candidate_P_from_ct(ct1)

    P = None; a = None; b = None
    for a_guess, P_guess in cands:
        # Validate with ct3
        b_guess = recover_x_from_ct_P(ct3, P_guess)
        if b_guess is not None:
            P, a, b = P_guess, a_guess, b_guess
            break

    if P is None:
        # Slow fallback: fully factor ct1 and try all divisor pairs (rare)
        fac = factor(ct1, [])
        # build all divisors
        from collections import Counter
        cnt = Counter(fac)
        divisors = [1]
        for p, e in cnt.items():
            new_divs = []
            powp = 1
            for _ in range(e+1):
                for d in divisors:
                    new_divs.append(d * powp)
                powp *= p
            divisors = new_divs
        divisors = [d for d in divisors if d <= ct1 // d]  # x <= y
        for x in sorted(divisors):
            y = ct1 // x
            P_guess = y - x
            b_guess = recover_x_from_ct_P(ct3, P_guess)
            if b_guess is not None:
                P, a, b = P_guess, x, b_guess
                break

    if P is None:
        raise RuntimeError("Failed to recover P. (Unexpected)")

    # Convert halves to bytes
    fl_bytes = long_to_bytes(a)
    ag_bytes = long_to_bytes(b)
    masked = fl_bytes + ag_bytes

    # Undo single-byte XOR key (0..125) with known prefix "FlagY{"
    k, flag = pick_key_from_masked(masked)
    if flag is None:
        # As a fallback, try all k 0..255 and require 'Flag{' just in case
        for kk in range(256):
            cand = bytes(b ^ kk for b in masked)
            if cand.startswith(b"Flag") and b"{" in cand[:8]:
                k, flag = kk, cand
                break

    if flag is None:
        raise RuntimeError("Could not determine XOR key / flag prefix mismatch.")

    print(flag.decode(errors="ignore"))

if __name__ == "__main__":
    main()
