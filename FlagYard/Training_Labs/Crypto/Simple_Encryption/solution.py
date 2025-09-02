#!/usr/bin/env python3
# decrypt_enc_scheme.py
# Solve for the 64-bit key and plaintext bytes using Z3 bit-vectors.

from z3 import BitVec, BitVecVal, ZeroExt, Solver, sat

# --- paste your ciphertext here ---
ct = [2, 73, 1279408694547274513244, 70105353946758363501802138205221132116, 272148444178645238255514677550260999012, 163070467820033153100988222221846406804, 86609496736369644722288034975639055628, 43128937165519816694258357152848494692, 320502000447316005409150167725211662724, 230178489086985152360072978627746714136, 51150919076204957128326106222833577076, 158240773363986558037607386784088940512, 304872496244635022312927683343945975156, 202848589728975784044527562137406231080, 7512389313575766780334514817734366976, 317213214347465770134647167616737395936, 151312341367906897735996944848577837928, 64442256831805280603281150422551063112, 46403079410007868840393933283231595664, 242473477743480427014125328686736940864, 53751688610473184360488785914556597624, 264175654134934177270269532228856344808, 59416574383127958958001760358914739208, 173626441680373497762981141808784854752, 96381203943555361752613580177449489792, 329162363675487685462360844964413481096, 193847948954369472983440009588539888552, 14450814094760923686146700048910753880, 198292150880585425958299965612615727776, 66786252247714141354755736365166242592, 78855848200194772380486016889274412456, 287550771686395960666144215762384325544, 297285574293655676309991420245534301208, 202501546131305814880557502943201564456, 151580341865118112418086843707020081216, 286941584051816509936971192867320835768, 303190756018448920035596127661477151272, 269171740993929521407477704933540132840, 184061349173849002083098988591970870992, 11968324907838152482831596404855563944, 307775715382277269039606144448918323720, 261495359018140595179051874736240188656, 88722822967841822844499727199659872248, 219857135538301014962603568439151933128, 190092548323415860089998932753848376480, 38870081668500098969220100832857729560, 87609724375251563632564845142147403848]

# -------------------------------------------------------------
# Model the encryption exactly:
#   o[0]=2, o[1]=73 (already in ct)
#   For i>=0: o[i+2] = ((key*o[i+1]) ^ (key + o[i]*p_i)) mod 2^128
# where key is 64-bit; p_i is 8-bit byte (0..255).
# -------------------------------------------------------------

def solve_key_and_plain(ct_list, printable_hint=False, timeout_ms=0):
    n_states = len(ct_list)
    if n_states < 3:
        raise ValueError("Ciphertext list must contain at least 3 integers (o0, o1, ...).")
    num_bytes = n_states - 2

    # Z3 bit-widths
    W128 = 128
    W64 = 64
    W8 = 8

    # Constants (128-bit)
    O = [BitVecVal(x % (1 << W128), W128) for x in ct_list]

    # Unknowns
    key64 = BitVec("key64", W64)
    key128 = ZeroExt(W128 - W64, key64)  # 128-bit view of key
    P = [BitVec(f"p_{i}", W8) for i in range(num_bytes)]

    s = Solver()
    if timeout_ms > 0:
        s.set("timeout", timeout_ms)

    # Optional: lightly guide plaintext to be readable for faster converge
    # (You can turn this off if you prefer fully unconstrained bytes.)
    if printable_hint:
        for i in range(num_bytes):
            # 9–10 (TAB/LF) allowed, 32–126 printable ASCII
            # p in {9,10} U [32..126]
            s.add(
                (P[i] == 9) |
                (P[i] == 10) |
                ((P[i] >= 32) & (P[i] <= 126))
            )

    # Core constraints from the recurrence
    for i in range(num_bytes):
        # ((key*o[i+1]) ^ (key + o[i]*p_i)) (all 128-bit, wraps automatically)
        lhs = (key128 * O[i+1]) ^ (key128 + (O[i] * ZeroExt(W128 - W8, P[i])))
        s.add(lhs == O[i+2])

    # Key is 64-bit uniform from randbelow(2**64)
    # (This is already enforced by BitVec width; no further constraint needed.)

    if s.check() != sat:
        return None

    m = s.model()
    key_val = m[key64].as_long() & ((1 << 64) - 1)
    p_bytes = bytes(int(m[P[i]].as_long() & 0xFF) for i in range(num_bytes))
    return key_val, p_bytes

def main():
    # Try with a mild printable hint first for speed; fallback without hints if needed.
    res = solve_key_and_plain(ct, printable_hint=True, timeout_ms=0)
    if res is None:
        # fallback: no printable assumptions
        res = solve_key_and_plain(ct, printable_hint=False, timeout_ms=0)

    if res is None:
        print("Failed to solve. Try running again without a timeout or remove any hints.")
        return

    key, pt = res
    try:
        decoded = pt.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        decoded = pt.decode("latin1", errors="replace")

    print(f"[+] Recovered key (unsigned 64-bit): {key}")
    print(f"[+] Plaintext bytes ({len(pt)}): {pt!r}")
    print(f"[+] Plaintext (decoded): {decoded}")

if __name__ == "__main__":
    main()
