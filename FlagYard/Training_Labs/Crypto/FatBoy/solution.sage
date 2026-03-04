#!/usr/bin/env sage
# =============================================================================
# FatBoy CTF Challenge - Solution
# Attack: Hastad Broadcast with Related Messages (Coppersmith small_roots + CRT)
# =============================================================================
#
# padcrypt(idx, m, key):
#   a = (3 + idx) * 2^1024
#   b = 5 * 2^1024 + idx * 4^1024
#   c = 8 * 2^1024 + idx * 6^1024
#   padded_m = a*m^2 + b*m + c
#   ciphertext = pow(padded_m, e, n)
#
# 11 log entries: same flag m, different RSA keys (e=5, n=1024-bit), idx=0..10
# Polynomial degree = 2*e = 10
# CRT combine -> G(x) ≡ 0 (mod N), N = product of all n_i
# small_roots finds m as a small root of G(x) mod N
#
# KEY INSIGHT: Do NOT pass X manually to small_roots! Let SageMath auto-compute
# it as X = ceil(0.5 * N^(1/d - epsilon)). Passing X = N^(1/d) fails because
# the lattice dimension m (from epsilon) only supports X up to N^(1/d - eps).
# =============================================================================

import json, base64
from Crypto.PublicKey import RSA

# Load log entries in original JSON order (idx = position in JSON)
with open("server_logs.json") as fh:
    logs = json.load(fh)

entries = []
for idx, log in enumerate(logs):
    k = RSA.import_key(base64.b64decode(log["key"]))
    entries.append({
        "idx": idx,
        "n":   Integer(k.n),
        "e":   Integer(k.e),
        "c":   Integer(int(log["c"], 16)),
    })

e = 5
R = ZZ["x"]
x = R.gen()

def make_poly(ent):
    """Build g_i(x) = f_i(x)^e - c_i where f_i is the padding polynomial."""
    i   = ent["idx"]
    ai  = Integer((3 + i) * 2**1024)
    bi  = Integer(5 * 2**1024 + i * 4**1024)
    cci = Integer(8 * 2**1024 + i * 6**1024)
    return (ai * x**2 + bi * x + cci)**e - ent["c"]

# CRT-combine all 11 polynomials -> G(x) ≡ 0 (mod N)
N = product(en["n"] for en in entries)
G = R(0)
for ent in entries:
    ni = ent["n"]
    Mi = N // ni
    yi = Integer(Mi).inverse_mod(ni)
    G += make_poly(ent) * Mi * yi
G = R([c % N for c in G.list()])

# Make monic (required by small_roots)
Gm = G.change_ring(Zmod(N))
lc = Integer(Gm.leading_coefficient())
Gm = Gm * lc.inverse_mod(N)

print(f"[*] N = {N.bit_length()} bits, polynomial degree = {Gm.degree()}")
print(f"[*] Running Coppersmith small_roots (eps=0.04, auto X)...")

# Find the flag as a small root — auto X ≈ 2^676 for k=11
roots = Gm.small_roots(beta=1.0, epsilon=0.04)
print(f"[*] Roots found: {len(roots)}")

for root in roots:
    m = int(root)
    if m > 0:
        flag_bytes = m.to_bytes((m.bit_length() + 7) // 8, "big")
        try:
            flag = flag_bytes.decode("utf-8")
            print(f"[+] Decoded: {flag}")
        except:
            print(f"[+] Raw bytes: {flag_bytes}")
