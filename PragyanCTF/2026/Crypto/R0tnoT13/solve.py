"""
Solve the AES internal state recovery challenge.

Given S XOR ROTR(S, k) for several even k values on a 128-bit state,
reconstruct S and decrypt the ciphertext.

Key insight: all k are even, so equations only link same-parity bits.
k=2 chains all even bits from s_0 and all odd bits from s_1.
Only 2 free bits -> 4 candidates to try.
"""

from Crypto.Cipher import AES

# ── Challenge data ──────────────────────────────────────────────────
frames = [
    (8,  183552667878302390742187834892988820241),
    (4,  303499033263465715696839767032360064630),
    (16, 206844958160238142919064580247611979450),
    (2,  163378902990129536295589118329764595602),
    (64, 105702179473185502572235663113526159091),
    (32, 230156190944614555973250270591375837085),
]

ct = bytes.fromhex("477eb79b46ef667f16ddd94ca933c7c0")

# ── Helpers ─────────────────────────────────────────────────────────
MASK128 = (1 << 128) - 1

def rotr(val, k, n=128):
    return ((val >> k) | (val << (n - k))) & MASK128

# ── Extract k=2 diagnostic bits ────────────────────────────────────
k2_val = next(val for k, val in frames if k == 2)
k2_bits = [(k2_val >> i) & 1 for i in range(128)]

# ── Brute force the 2 anchor bits and try decryption ───────────────
print("="*60)
print("Trying all 4 anchor-bit combinations (s0, s1)")
print("="*60)

for s0 in range(2):
    for s1 in range(2):
        # Reconstruct all 128 bits from k=2 chain
        s = [0] * 128
        s[0] = s0
        s[1] = s1
        for j in range(1, 64):
            s[2*j]   = s[2*(j-1)]   ^ k2_bits[2*(j-1)]
            s[2*j+1] = s[2*(j-1)+1] ^ k2_bits[2*(j-1)+1]

        S = sum(s[i] << i for i in range(128))

        # Verify against ALL frames
        valid = all(S ^ rotr(S, k) == val for k, val in frames)

        print(f"\ns0={s0}, s1={s1}  valid={valid}")
        if not valid:
            continue

        print(f"  S = {S}")
        print(f"  S (hex) = {S:032x}")

        # 1) Direct XOR with state bytes (big-endian)
        S_bytes_be = S.to_bytes(16, 'big')
        pt_xor = bytes(a ^ b for a, b in zip(ct, S_bytes_be))
        print(f"  XOR(big):  {pt_xor.hex()}  |  {pt_xor}")
        if all(0x20 <= b < 0x7f for b in pt_xor):
            print(f"  >>> ALL PRINTABLE: {pt_xor.decode()}")

        # 2) Direct XOR with state bytes (little-endian)
        S_bytes_le = S.to_bytes(16, 'little')
        pt_xor_le = bytes(a ^ b for a, b in zip(ct, S_bytes_le))
        print(f"  XOR(lit):  {pt_xor_le.hex()}  |  {pt_xor_le}")
        if all(0x20 <= b < 0x7f for b in pt_xor_le):
            print(f"  >>> ALL PRINTABLE: {pt_xor_le.decode()}")

        # 3) AES-ECB decrypt
        for endian in ('big', 'little'):
            key = S.to_bytes(16, endian)
            cipher = AES.new(key, AES.MODE_ECB)
            pt_ecb = cipher.decrypt(ct)
            if all(0x20 <= b < 0x7f for b in pt_ecb):
                print(f"  AES-ECB({endian}): >>> {pt_ecb.decode()}")

            # AES-CTR (counter = 0)
            pt_ctr = bytes(a ^ b for a, b in zip(ct, cipher.encrypt(b'\x00'*16)))
            if all(0x20 <= b < 0x7f for b in pt_ctr):
                print(f"  AES-CTR({endian}): >>> {pt_ctr.decode()}")

print("\n" + "="*60)
print("Done.")
