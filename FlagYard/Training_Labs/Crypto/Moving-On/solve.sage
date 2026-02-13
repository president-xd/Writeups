from Crypto.Util.number import long_to_bytes
from sage.libs.pari import pari

p = 0x00e675aaef519c7bdfa7e9b6d5
a = 0x00c5a83d2b9ce92d9c75a37a08
b = 0x0020cd6dc3b4b34e4332463ccd

E = EllipticCurve(GF(p), [a, b])
G = E.gens()[0]
n_G = G.order()

Q1 = E(25868279382606376233089622039, 35226758373642087968613953852)
Q2 = E(31211278741961598848732755066, 68653856268530027481128223450)

print(f"[*] Supersingular curve, #E = {E.order()} = p+1")
print(f"[*] ord(G) = {n_G}")
print(f"[*] Using PARI elllog (optimized C, handles MOV internally)\n")

# PARI's elllog is fully implemented in C and automatically applies
# the MOV attack for supersingular curves + Pollard's rho for large factors
E_pari = E.__pari__()
G_pari = G.__pari__()

print("[*] Solving ECDLP for Q1...", flush=True)
s1 = ZZ(pari.elllog(E_pari, Q1.__pari__(), G_pari, n_G))
assert s1 * G == Q1, "Verification failed for s1!"
print(f"[+] s1 = {s1}  [VERIFIED]\n")

print("[*] Solving ECDLP for Q2...", flush=True)
s2 = ZZ(pari.elllog(E_pari, Q2.__pari__(), G_pari, n_G))
assert s2 * G == Q2, "Verification failed for s2!"
print(f"[+] s2 = {s2}  [VERIFIED]\n")

# Reconstruct flag
flag = long_to_bytes(int(s1)) + long_to_bytes(int(s2))

# Remove PKCS7 padding
pad_byte = flag[-1]
if 1 <= pad_byte <= 12 and all(b == pad_byte for b in flag[-pad_byte:]):
    flag = flag[:-pad_byte]

print(f"[+] Flag: {flag}")
try:
    print(f"[+] Flag (decoded): {flag.decode()}")
except:
    pass
