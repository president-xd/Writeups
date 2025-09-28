#!/usr/bin/env python3
# Recover AES-CBC key/iv from one linear leakage using LLL (no external deps except pycryptodome for AES)
# Usage: python3 solve_crypto.py [path_to_output.txt]
import sys, re
from fractions import Fraction

def parse_input(text:str):
    def grab(label):
        m = re.search(rf'^{label}\s*=\s*(.+)$', text, flags=re.M)
        if not m: raise ValueError(f"Missing {label}")
        v = m.group(1).strip()
        if label != "ct":
            if "..." in v: raise ValueError("Numbers appear truncated (contain '...'). Provide full values.")
            return int(v)
        else:
            return v.strip().strip("'\"")
    return grab("a"), grab("b"), grab("c"), grab("ct")

def gram_schmidt(B):
    from fractions import Fraction
    n = len(B); m = len(B[0])
    B_star = [[Fraction(0) for _ in range(m)] for _ in range(n)]
    mu = [[Fraction(0) for _ in range(n)] for _ in range(n)]
    norm = [Fraction(0) for _ in range(n)]
    for i in range(n):
        B_star[i] = [Fraction(x) for x in B[i]]
        for j in range(i):
            num = sum(Fraction(B[i][k]) * B_star[j][k] for k in range(m))
            den = sum(B_star[j][k] * B_star[j][k] for k in range(m))
            mu[i][j] = num / den if den != 0 else Fraction(0)
            for k in range(m):
                B_star[i][k] -= mu[i][j] * B_star[j][k]
        norm[i] = sum(B_star[i][k] * B_star[i][k] for k in range(m))
    return B_star, mu, norm

def lll_reduction(B, delta=Fraction(3,4)):
    B = [list(map(int, row)) for row in B]
    n = len(B); m = len(B[0])
    B_star, mu, norm = gram_schmidt(B)
    k = 1
    while k < n:
        for j in range(k-1, -1, -1):
            q = int(round(mu[k][j]))
            if q != 0:
                for t in range(m):
                    B[k][t] -= q * B[j][t]
                B_star, mu, norm = gram_schmidt(B)
        if norm[k] >= (delta - mu[k][k-1]**2) * norm[k-1]:
            k += 1
        else:
            B[k], B[k-1] = B[k-1], B[k]
            B_star, mu, norm = gram_schmidt(B)
            k = max(k-1, 1)
    return B

def solve_from_abc(a,b,c):
    B = [
        [a, 0, 0],
        [b, 1, 0],
        [c, 0, 1],
    ]
    Bred = lll_reduction(B)
    cand = [row for row in Bred if abs(row[2])==1] or Bred
    best = min(cand, key=lambda v: v[0]*v[0]+v[1]*v[1])
    noise = abs(int(best[0]))
    key   = abs(int(best[1]))
    iv    = (c - b*key - noise)//a
    assert c - (a*iv + b*key) == noise
    assert key.bit_length() <= 128 and iv.bit_length() <= 128 and noise.bit_length() <= 128
    return key, iv, noise

def decrypt_flag(key, iv, ct_hex):
    key_bytes = bytes.fromhex(f"{key:x}")
    iv_bytes  = bytes.fromhex(f"{iv:x}")
    ct = bytes.fromhex(ct_hex)
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
    except Exception:
        try:
            from Cryptodome.Cipher import AES
            from Cryptodome.Util.Padding import unpad
        except Exception:
            raise SystemExit("PyCryptodome required: pip install pycryptodome")
    return unpad(AES.new(key_bytes, AES.MODE_CBC, iv_bytes).decrypt(ct), 16)

def main():
    import pathlib
    p = pathlib.Path(sys.argv[1]) if len(sys.argv)>1 else pathlib.Path("output.txt")
    a,b,c,ct_hex = parse_input(p.read_text(encoding="utf-8"))
    key, iv, noise = solve_from_abc(a,b,c)
    pt = decrypt_flag(key, iv, ct_hex)
    print("key =", key)
    print("iv  =", iv)
    print("noise =", noise)
    print("FLAG:", pt.decode())

if __name__ == "__main__":
    main()
