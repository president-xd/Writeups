# quadratic_crt_solve.py
# Reconstruct F from:
#   y1, y2 in Z[a]  (with a^2 = -7)
#   m1 = v1 + u1*a, m2 = v2 + u2*a
# and y_i ≡ F*a (mod m_i)

from math import gcd

# -------- ring ops in Z[a]/(a^2 + 7) --------
def mul(x, y):
    (p1, q1), (p2, q2) = x, y            # x = p1 + q1*a, y = p2 + q2*a
    return (p1*p2 - 7*q1*q2, p1*q2 + p2*q1)

def norm(m):                              # m = v + u*a
    v, u = m
    return v*v + 7*u*u

# Inverse of 'a' modulo the ideal (m) with m = v + u*a
# We construct a solution to a*(x + y*a) ≡ 1 (mod m) by picking r s.t. v*r ≡ -1 (mod 7)
def inv_a_mod(m):
    v, u = m
    vm7 = v % 7
    if gcd(vm7, 7) != 1:
        raise ValueError("v not invertible mod 7; cannot build a^{-1} mod m")
    r = next(r for r in range(7) if (vm7 * r) % 7 == 6)  # ≡ -1 mod 7
    x = u * r
    y = -(v * r + 1) // 7
    return (x, y)                         # x + y*a

# Given z ≡ F (an integer) mod (m), extract F mod N by solving
#   z - (p,0) ∈ (m). If m = v + u*a, write (r + s*a)*m and match coefficients:
#     z.q = r*u + s*v, then p = z.p - (r*v - 7*s*u)  (unique mod N = N(m))
def int_rep_from_class(z, m):
    v, u = m
    zp, zq = z

    def egcd(a, b):
        if b == 0: return (1, 0, a)
        x1, y1, g = egcd(b, a % b)
        return (y1, x1 - (a // b) * y1, g)

    x, y, g = egcd(u, v)
    if zq % g != 0:
        raise ValueError("No solution to r*u + s*v = zq")
    r0 = x * (zq // g)
    s0 = y * (zq // g)
    p = zp - (r0 * v - 7 * s0 * u)
    return p % norm(m), norm(m)

def modinv(a, m):
    a %= m
    if a == 0: raise ValueError("no inverse")
    t0, t1, r0, r1 = 0, 1, m, a
    while r1:
        q = r0 // r1
        t0, t1, r0, r1 = t1, t0 - q*t1, r1, r0 - q*r1
    if r0 != 1: raise ValueError("no inverse")
    return t0 % m

def crt(a1, n1, a2, n2):
    # solves x = a1 (mod n1), x = a2 (mod n2)
    g = gcd(n1, n2)
    if (a1 - a2) % g != 0:
        raise ValueError("CRT: no solution")
    n1p, n2p = n1 // g, n2 // g
    inv = modinv(n1p % n2p, n2p)
    x = (a1 + ((a2 - a1) // g % n2p) * inv % n2p * n1) % (n1 * n2p)
    return x, n1 * n2p

# ---- parse your output.txt (format shown in your file) ----
def parse_elem(s):
    s = s.replace(" ", "")
    if "*a+" in s:
        coef_a, const = s.split("*a+")
        return (int(const), int(coef_a))
    elif s.endswith("*a"):
        return (0, int(s[:-2]))
    else:
        return (int(s), 0)

def load_io(path="output.txt"):
    vals = {}
    with open(path, "r") as f:
        for line in f:
            if "=" not in line: continue
            k, v = line.split("=", 1)
            vals[k.strip()] = v.strip()
    y1 = parse_elem(vals["y1"])
    y2 = parse_elem(vals["y2"])
    m1 = parse_elem(vals["m1"])  # (v1, u1)
    m2 = parse_elem(vals["m2"])  # (v2, u2)
    return y1, y2, m1, m2

def main():
    y1, y2, m1, m2 = load_io("output.txt")

    # Step 1: z_i = y_i * a^{-1} (mod m_i) but we can compute z_i in Z[a] first
    inva1 = inv_a_mod(m1)
    inva2 = inv_a_mod(m2)
    z1 = mul(y1, inva1)
    z2 = mul(y2, inva2)

    # Step 2: extract the integer representative F modulo each norm N(m_i)
    F1, N1 = int_rep_from_class(z1, m1)
    F2, N2 = int_rep_from_class(z2, m2)

    # Step 3: CRT to get F modulo lcm(N1, N2)
    F, _ = crt(F1, N1, F2, N2)

    # Step 4: emit the 64-byte message
    b = F.to_bytes(64, "big")
    print("F (hex):", b.hex())
    try:
        print("F (utf-8, errors=ignore):", b.decode("utf-8", errors="ignore"))
    except Exception:
        pass

    # Save to files
    open("recovered_F.bin", "wb").write(b)
    open("recovered_F.hex.txt", "w").write(b.hex())

if __name__ == "__main__":
    main()