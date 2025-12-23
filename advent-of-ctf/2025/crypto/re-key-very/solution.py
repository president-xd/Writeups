#!/usr/bin/env python3
import hashlib

# secp256k1 curve order
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def inv_mod(a, m=n):
    return pow(a % m, m - 2, m)

def H(m: bytes) -> int:
    return int.from_bytes(hashlib.sha256(m).digest(), "big")

# Given transcripts
msgs = [
    b"Beware the Krampus Syndicate!",
    b"Santa is watching...",
    b"Good luck getting the key",
]

r_hex = [
    "a4312e31e6803220d694d1040391e8b7cc25a9b2592245fb586ce90a2b010b63",
    "6c5f7047d21df064b3294de7d117dd1f7ccf5af872d053f12bddd4c6eb9f6192",
    "2c15aceb49e63e4a2c8357102fbd345ac2cbd1b214c77fba0cd9ffe8d20d2c1e",
]
s_hex = [
    "e54321716f79543591ab4c67e989af3af301e62b3b70354b04e429d57f85aa2e",
    "1ccf403d4a520bc3822c300516da8b29be93423ab544fb8dbff24ca0e1368367",
    "1ee49ef3857ad1d9ff3109bfb4a91cb464ab6fdc88ace610ead7e6dee0957d95",
]

r = [int(x, 16) for x in r_hex]
s = [int(x, 16) for x in s_hex]
z = [H(m) for m in msgs]

# ECDSA: s_i = k_i^{-1} (z_i + r_i d) mod n
# => r_i d = s_i k_i - z_i mod n
# Here k1 = k0+1, k2 = k0+2 (mod n).

def solve_k0_from_pair(i, j, delta):
    """
    Uses signatures i and j where k_j = k_i + delta (delta known small int).
    Derivation:
      (s_i*k - z_i)/r_i == (s_j*(k+delta) - z_j)/r_j  (mod n)
    Solve linear for k.
    """
    ri, rj = r[i] % n, r[j] % n
    si, sj = s[i] % n, s[j] % n
    zi, zj = z[i] % n, z[j] % n

    # (rj*si - ri*sj) * k = ri*sj*delta - ri*zj + rj*zi   (mod n)
    coeff = (rj * si - ri * sj) % n
    rhs   = (ri * sj * (delta % n) - ri * zj + rj * zi) % n
    if coeff == 0:
        return None
    return (rhs * inv_mod(coeff, n)) % n

def recover_key():
    # Try (0,1) with delta=1; fallback to other pairs if needed.
    candidates = [
        solve_k0_from_pair(0, 1, 1),
        solve_k0_from_pair(1, 2, 1),
        solve_k0_from_pair(0, 2, 2),
    ]
    candidates = [c for c in candidates if c is not None]
    if not candidates:
        raise RuntimeError("Failed to solve for k0 (singular coefficients).")

    for k0 in candidates:
        # compute d from first signature: d = (s0*k0 - z0) * r0^{-1} mod n
        d = ((s[0] * k0 - z[0]) % n) * inv_mod(r[0], n) % n

        # quick consistency check across all three:
        ok = True
        for idx in range(3):
            ki = (k0 + idx) % n
            lhs = (r[idx] * d) % n
            rhs = (s[idx] * ki - z[idx]) % n
            if lhs != rhs:
                ok = False
                break
        if ok:
            return k0, d

    raise RuntimeError("No candidate k0 produced a consistent private key.")

k0, d = recover_key()

print("[+] Recovered k0:", k0)
print("[+] Recovered private key d:", d)
d_bytes = d.to_bytes(32, "big")
print("[+] d (32-byte hex):", d_bytes.hex())

# In the challenge, d came from int.from_bytes(key,'big') with a reduction into [1..n-1].
# Often the flag/key bytes are directly embedded. Try printing as ASCII if possible.
try:
    print("[+] d bytes as utf-8:", d_bytes.decode("utf-8"))
except UnicodeDecodeError:
    print("[+] d bytes not valid utf-8; raw bytes shown above.")
