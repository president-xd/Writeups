#!/usr/bin/env sage
# Solve super-67-prime RSA given n and c
# Usage: sage solve.sage <n> <c>
import sys

if len(sys.argv) < 3:
    print("Usage: sage solve.sage <n> <c>")
    sys.exit(1)

n = int(sys.argv[1])
c = int(sys.argv[2])
e = 65537

print(f"[*] n is {int(n).bit_length()} bits")

# p = "6"*67 + middle + "7"*67, where middle digits are each 6 or 7
# Let p = base + delta * 10^67 where base = int("6"*134 + "7"*67)
# delta ranges from 0 to (10^67-1)/9 (=repunit(67)) ~ 2^219

base = int("6"*134 + "7"*67)

P.<x> = PolynomialRing(Zmod(n))
# f(x) = base + x*10^67  has root delta mod p, which divides n
# Make monic: divide by 10^67
inv_coeff = inverse_mod(int(10^67), n)
f_monic = x + int(base) * inv_coeff
X = (10^67 - 1) // 9 + 1

print(f"[*] Running Coppersmith (X ~ 2^{int(X).bit_length()} bits)...")
print("[*] This may take a minute...")

# Try with increasing epsilon (larger = faster but less likely to succeed)
for eps in [0.05, 0.03, 0.02, 0.01]:
    print(f"[*] Trying epsilon={eps}...")
    try:
        roots = f_monic.small_roots(X=X, beta=0.49, epsilon=eps)
        if roots:
            print(f"[*] Found {len(roots)} root(s) with eps={eps}")
            break
    except Exception as ex:
        print(f"[*] eps={eps} failed: {ex}")
        continue
else:
    print("[-] No roots found with any parameters")
    sys.exit(1)

for r in roots:
    delta = int(r)
    p_cand = base + delta * 10^67
    if n % p_cand == 0:
        q = n // p_cand
        phi = (p_cand - 1) * (q - 1)
        d = int(inverse_mod(e, phi))
        m = int(pow(c, d, n))
        flag = m.to_bytes((m.bit_length() + 7) // 8, 'big')
        print(f"\n[+] p = {p_cand}")
        print(f"[+] q = {q}")
        try:
            print(f"[+] FLAG: {flag.decode()}")
        except:
            print(f"[+] FLAG (bytes): {flag}")
        sys.exit(0)

print("[-] Root found but doesn't divide n")
