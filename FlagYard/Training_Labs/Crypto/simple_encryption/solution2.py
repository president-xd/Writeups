#!/usr/bin/env python3
# decrypt_enc_scheme.py
# Read ct from output.txt, recover 64-bit key + plaintext via Z3 bit-vectors.

import sys
import ast
from z3 import BitVec, BitVecVal, ZeroExt, Solver, sat

def load_ct(path="output.txt"):
    with open(path, "r", encoding="utf-8") as f:
        data = f.read().strip()
    ct = ast.literal_eval(data)  # expects a Python-style list of ints
    if not isinstance(ct, list) or len(ct) < 3:
        raise ValueError("Ciphertext must be a Python list with at least 3 integers.")
    return ct

def solve_key_and_plain(ct_list, printable_hint=True, timeout_ms=0):
    """
    Model the recurrence exactly (mod 2^128):
      o[0]=2, o[1]=73 are given.
      For i>=0: o[i+2] = ((key*o[i+1]) ^ (key + o[i]*p_i)) mod 2^128
      key is 64-bit; each p_i is 8-bit.
    """
    W128, W64, W8 = 128, 64, 8
    O = [BitVecVal(x % (1 << W128), W128) for x in ct_list]
    num_bytes = len(ct_list) - 2

    key64 = BitVec("key64", W64)
    key128 = ZeroExt(W128 - W64, key64)
    P = [BitVec(f"p_{i}", W8) for i in range(num_bytes)]

    s = Solver()
    if timeout_ms > 0:
        s.set("timeout", timeout_ms)

    # Optional speed-up: nudge bytes toward printable ASCII (keeps it general)
    if printable_hint:
        for i in range(num_bytes):
            s.add(
                (P[i] == 9) | (P[i] == 10) | (P[i] == 13) |  # allow TAB/LF/CR
                ((P[i] >= 32) & (P[i] <= 126))              # printable ASCII
            )

    for i in range(num_bytes):
        # ((key*o[i+1]) ^ (key + o[i]*p_i)) == o[i+2]  (all 128-bit)
        lhs = (key128 * O[i+1]) ^ (key128 + (O[i] * ZeroExt(W128 - W8, P[i])))
        s.add(lhs == O[i+2])

    if s.check() != sat:
        return None

    m = s.model()
    key_val = m[key64].as_long() & ((1 << 64) - 1)
    pt_bytes = bytes(int(m[P[i]].as_long() & 0xFF) for i in range(num_bytes))
    return key_val, pt_bytes

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "output.txt"
    ct = load_ct(path)

    # Try with printable hint first; fall back to fully unconstrained if needed.
    res = solve_key_and_plain(ct, printable_hint=True, timeout_ms=0)
    if res is None:
        res = solve_key_and_plain(ct, printable_hint=False, timeout_ms=0)

    if res is None:
        print("[-] UNSAT: could not solve. Try removing timeouts or hints.")
        sys.exit(1)

    key, pt = res
    try:
        decoded = pt.decode("utf-8")
    except UnicodeDecodeError:
        decoded = pt.decode("latin1", errors="replace")

    print(f"[+] Recovered key (u64): {key} (0x{key:016x})")
    print(f"[+] Plaintext bytes ({len(pt)}): {pt!r}")
    print(f"[+] Plaintext: {decoded}")

if __name__ == "__main__":
    main()
