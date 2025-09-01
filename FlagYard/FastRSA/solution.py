#!/usr/bin/env python3
import sys
import re

# ---------- number theory helpers ----------
def egcd(a, b):
    if b == 0:
        return (abs(a), 1 if a >= 0 else -1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def inv_mod(a, n):
    g, x, _ = egcd(a, n)
    if g != 1:
        return None
    return x % n

def solve_linear_congruence(a, b, n):
    """Solve a*x ≡ b (mod n). Returns (x0, mod) or None."""
    g, x, _ = egcd(a, n)
    if b % g != 0:
        return None
    a_, b_, n_ = a // g, b // g, n // g
    x0 = (x * b_) % n_
    return (x0, n_)

# ---------- core recovery (no factoring!) ----------
def recover_m(n, c0, c1):
    """
    Given n, c0 = m^3 mod n, c1 = (m+1)^3 mod n, recover m.
    Uses the polynomial remainder trick; typically just one inversion mod n.
    """
    t = (1 + c0 - c1) % n  # t = 1 + c0 - c1

    inv3 = inv_mod(3, n)
    if inv3 is not None:
        T = (inv3 * t) % n
        A = (1 - T) % n
        B = (T - c0) % n

        invA = inv_mod(A, n)
        if invA is not None:
            return (-B * invA) % n

        # Rare: A not invertible — solve linear congruence generally
        sol = solve_linear_congruence(A, (-B) % n, n)
        if sol is None:
            raise ValueError("No solution to linear congruence (unexpected).")
        x0, mod = sol
        # Try all lifts
        g = n // mod
        for k in range(g):
            cand = (x0 + k * mod) % n
            if pow(cand, 3, n) == c0 and pow((cand + 1) % n, 3, n) == c1:
                return cand
        raise ValueError("No valid m among lifts (unexpected).")

    # Extremely unlikely fallback if 3 | n
    A_int = (3 - t) % (3 * n)
    B_int = (3 * c0 - t) % (3 * n)
    sol = solve_linear_congruence(A_int, B_int, 3 * n)
    if sol is None:
        raise ValueError("No solution when 3|n (unexpected).")
    x0, mod = sol
    for k in range(3):  # try a few lifts, verify
        cand = (x0 + k * mod) % n
        if pow(cand, 3, n) == c0 and pow((cand + 1) % n, 3, n) == c1:
            return cand
    raise ValueError("Failed to verify m when 3|n.")

# ---------- robust stream parser ----------
def main():
    buf = []
    int_re = re.compile(r'-?\d+')

    while True:
        line = sys.stdin.readline()
        if not line:  # EOF
            break

        # Extract any integers on this line (ignore everything else)
        for tok in int_re.findall(line):
            try:
                buf.append(int(tok))
            except ValueError:
                pass

        # When we have at least 3 integers, treat them as (n, c0, c1)
        while len(buf) >= 3:
            n, c0, c1 = buf[0], buf[1], buf[2]
            # Compute m and send it immediately
            try:
                m = recover_m(n, c0 % n, c1 % n)
            except Exception as e:
                # If something went wrong, dump a safe number to avoid timeouts
                # (you can also print an error to stderr for debugging)
                # sys.stderr.write(f"[!] Error: {e}\n")
                m = 0

            print(m, flush=True)
            # Consume exactly these three numbers; keep any extra ints (unlikely)
            buf = buf[3:]

if __name__ == "__main__":
    main()
