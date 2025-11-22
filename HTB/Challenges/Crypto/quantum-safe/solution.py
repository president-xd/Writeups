#!/usr/bin/env python3
from fractions import Fraction
import re

# === Known public key matrix (from the challenge) ===
# pubkey = Matrix(ZZ, [
#     [47, -77, -85],
#     [-49, 78, 50],
#     [57, -78, 99]
# ])
#
# We precomputed its inverse over Q:
Minv = [
    [Fraction(3874, 2099), Fraction(4751, 2099), Fraction(2780, 6297)],
    [Fraction(2567, 2099), Fraction(3166, 2099), Fraction(605, 2099)],
    [Fraction(-208, 2099), Fraction(-241, 2099), Fraction(-107, 6297)],
]


def row_mul(row, Minv):
    """Multiply 1x3 row vector with 3x3 Minv (over rationals)."""
    res = []
    for col in range(3):
        s = Fraction(0, 1)
        for j in range(3):
            s += row[j] * Minv[j][col]
        res.append(s)
    return res


def frac_part(f: Fraction) -> Fraction:
    """Fractional part of a rational number."""
    return f - int(f)


def main():
    # === 1. Read ciphertext vectors from output.txt ===
    cts = []
    with open("output.txt") as f:
        for line in f:
            nums = list(map(int, re.findall(r"-?\d+", line)))
            if len(nums) == 3:
                cts.append(nums)

    if not cts:
        print("No ciphertext vectors found in output.txt")
        return

    # === 2. Compute z_i = (cipher_i) * Minv ===
    Z = [row_mul(row, Minv) for row in cts]

    # === 3. Extract and remove constant fractional offset (r * Minv) ===
    # Fractional parts are the same for all rows in each coordinate.
    t_frac = [frac_part(Z[0][i]) for i in range(3)]
    for v in Z:
        assert [frac_part(v[i]) for i in range(3)] == t_frac

    # X_i' = x_i + k, where x_i = (ord(c), rand1, rand2), k is unknown integer vector
    X = []
    for v in Z:
        xi = [v[i] - t_frac[i] for i in range(3)]
        X.append([int(val) for val in xi])

    # === 4. Use the bounds on the random components (0..100) to pin down k2, k3 ===
    cols = list(zip(*X))
    mins = [min(col) for col in cols]
    maxs = [max(col) for col in cols]

    # rand coords originally in [0, 100]
    # so X[:,1] - k2, X[:,2] - k3 must lie in [0,100]
    # => k2 in [mins[1] - 100, mins[1]], similarly for k3
    candidates = []

    for k2 in range(mins[1] - 100, mins[1] + 1):
        for k3 in range(mins[2] - 100, mins[2] + 1):
            # quick pre-check for coords 2 & 3
            ok23 = True
            for x in X:
                a = x[1] - k2
                b = x[2] - k3
                if not (0 <= a <= 100 and 0 <= b <= 100):
                    ok23 = False
                    break
            if not ok23:
                continue

            # Now brute k1, requiring printable ASCII for all characters
            # ord(c) in [32, 126]
            first_x0 = X[0][0]
            for k1 in range(first_x0 - 126, first_x0 - 31):
                chars = []
                ok = True
                for x in X:
                    m = x[0] - k1
                    if not (32 <= m <= 126):
                        ok = False
                        break
                    chars.append(chr(m))
                if ok:
                    s = "".join(chars)
                    candidates.append((k1, k2, k3, s))

    # === 5. Print all candidates and highlight one that looks like a flag ===
    unique_plaintexts = sorted(set(s for _, _, _, s in candidates))

    print("Found plaintext candidates:\n")
    for s in unique_plaintexts:
        print(s)

    # If it's an HTB-style challenge, auto-detect HTB flag:
    for s in unique_plaintexts:
        if "HTB{" in s:
            print("\nLikely flag:", s)
            break


if __name__ == "__main__":
    main()
