#!/usr/bin/env python3
from pwn import remote, context
import json, time

context.log_level = "error"

# ---- constants from challenge ----
# chars = printable[:62] + "-_"
chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_"
assert len(chars) == 64
c2i = {c:i for i,c in enumerate(chars)}
i2c = {i:c for i,c in enumerate(chars)}

USER_LEN = 32
USER_LEN_BYTES = 3 * USER_LEN // 4  # 24
N_BITS = 8 * USER_LEN_BYTES         # 192 bits controllable via username prefix

def safe_json_loads(line: bytes):
    try:
        return json.loads(line.decode(errors="ignore"))
    except Exception:
        return None

def jrecv(io):
    """Read lines until we get valid JSON dict, or raise EOF."""
    while True:
        line = io.recvline(timeout=5)
        if not line:
            raise EOFError("No data / connection closed while waiting for JSON")
        obj = safe_json_loads(line)
        if isinstance(obj, dict):
            return obj

def jsend(io, obj):
    io.sendline(json.dumps(obj).encode())

def compress(username: str) -> bytes:
    # exact logic from challenge: enumerate(username.rjust(32,"_")), sum(index<<6*i)
    u = username.rjust(USER_LEN, "_")
    x = 0
    for i, ch in enumerate(u):
        x += c2i[ch] << (6 * i)
    # Challenge uses big-endian (default for int.to_bytes)
    return x.to_bytes(USER_LEN_BYTES, "big")

def make_username_with_flip(base_u: str, bit_k: int) -> str:
    """Flip bit_k in the 192-bit compressed prefix by toggling a bit inside a 6-bit char index."""
    u = list(base_u.rjust(USER_LEN, "_"))
    chunk = bit_k // 6   # which 6-bit character
    b = bit_k % 6

    idx = chunk  # chunk 0 corresponds to leftmost char of the rjust'd string due to enumerate
    val = c2i[u[idx]] ^ (1 << b)
    u[idx] = i2c[val]
    out = "".join(u)

    # username must start with chars[:62] (alnum) per challenge
    if out[0] not in chars[:62]:
        # tweak base username if this happens (rare if base[0] is stable)
        raise ValueError("first char constraint violated; choose another base username")
    return out

def int_from_hex32(hx: str) -> int:
    return int.from_bytes(bytes.fromhex(hx), "big")

def abs_tag(x: int, p: int) -> int:
    return x if x <= p // 2 else p - x
def int_from_compressed(b: bytes) -> int:
    """Convert compressed bytes back to integer value - big-endian"""
    return int.from_bytes(b, "big")
def try_parse_pg(msg: dict):
    # Some servers include p/g in output JSON. Try multiple keys.
    for pk in ["p", "prime", "P"]:
        for gk in ["g", "gen", "G"]:
            if pk in msg and gk in msg:
                try:
                    return int(msg[pk]), int(msg[gk])
                except Exception:
                    pass
    return None, None

def register(io, username, password, data="x"):
    jsend(io, {"option":"register","username":username,"password":password,"data":data})
    r = jrecv(io)
    if r.get("out") != "registered":
        # allow "username taken" (if rerun)
        if r.get("out") != "username taken":
            raise RuntimeError(f"register failed: {r}")

def login(io, username, password):
    jsend(io, {"option":"login","username":username,"password":password})
    r = jrecv(io)
    if r.get("out") != "logged in":
        raise RuntimeError(f"login failed: {r}")
    return r["info"], r["mac"]

def read_admin(io, info_hex, mac_hex):
    jsend(io, {"option":"read","username":"admin","info":info_hex,"mac":mac_hex})
    return jrecv(io)

def recover_s192(io, p, g, base_user, pw, flip_users):
    """
    Recover the 192 bits of s affecting the prefix using per-bit paired logins.
    Uses squaring to remove the ± from abs().
    """
    s = 0
    g2 = pow(g, 2, p)

    for k in range(N_BITS):
        u_flip = flip_users[k]

        # get a pair of tokens that share the same expiry bytes (same second)
        attempts = 0
        while True:
            info0, mac0 = login(io, base_user, pw)
            info1, mac1 = login(io, u_flip, pw)

            b0 = bytes.fromhex(info0)
            b1 = bytes.fromhex(info1)
            exp0 = b0[USER_LEN_BYTES:]
            exp1 = b1[USER_LEN_BYTES:]
            if exp0 == exp1:
                if k == 0:  # Debug first bit
                    print(f"[DEBUG] info0={info0}")
                    print(f"[DEBUG] info1={info1}")
                    print(f"[DEBUG] mac0={mac0}")
                    print(f"[DEBUG] mac1={mac1}")
                    print(f"[DEBUG] exp0==exp1: {exp0.hex()}")
                break
            attempts += 1
            if attempts > 100:
                raise RuntimeError(f"Could not get matching expiry for bit {k}")

        t0 = int_from_hex32(mac0)
        t1 = int_from_hex32(mac1)

        # square tags to kill sign: (±x)^2 == x^2
        t0s = pow(t0, 2, p)
        t1s = pow(t1, 2, p)

        ratio = (t1s * pow(t0s, -1, p)) % p

        # The prefix is 24 bytes, expiry is 8 bytes.
        # When converted to int (big-endian), the prefix occupies the high 192 bits,
        # and expiry occupies the low 64 bits.
        # So bit k in the prefix corresponds to bit (k + 64) in the full 256-bit integer.
        # Therefore, flipping bit k in prefix causes a difference of 2^(k+64) in the full int.
        # After XOR with s, the exponent difference is 2^(k+64).
        # After squaring, the ratio is g^(±2^(k+65)).
        
        a = pow(g2, 1 << (k + 64), p)      # g^(2^(k+65))
        ainv = pow(a, -1, p)

        # m0[k+64] is bit k of base_pref_int
        m0_bit = (int.from_bytes(compress(base_user), "big") >> k) & 1
        
        if ratio == a:
            # e0[k+64] = 0, so m0[k+64] = s[k+64]
            s |= (m0_bit << k)
        elif ratio == ainv:
            # e0[k+64] = 1, so m0[k+64] != s[k+64]
            s |= ((1 - m0_bit) << k)
        else:
            # Debug: print the actual values to diagnose
            if k < 5:
                print(f"[DEBUG] bit {k}: ratio={ratio}, a={a}, ainv={ainv}")
                print(f"        ratio==1? {ratio==1}, ratio==p-1? {ratio==p-1}")
            raise RuntimeError(f"Unexpected ratio at bit {k} (desync/endian mismatch?)")

        if k % 16 == 15:
            print(f"[+] recovered {k+1}/192 bits")

    return s

def forge_admin(p, g, s192, base_info_hex, base_mac_hex, base_user):
    base_info = bytes.fromhex(base_info_hex)
    expiry = base_info[USER_LEN_BYTES:]                 # 8 bytes
    base_prefix = base_info[:USER_LEN_BYTES]
    admin_prefix = compress("admin")

    base_pref_int = int.from_bytes(base_prefix, "big")
    admin_pref_int = int.from_bytes(admin_prefix, "big")

    diff = base_pref_int ^ admin_pref_int
    
    print(f"[FORGE DEBUG] base_pref_int: {hex(base_pref_int)}")
    print(f"[FORGE DEBUG] admin_pref_int: {hex(admin_pref_int)}")
    print(f"[FORGE DEBUG] diff: {hex(diff)}")
    print(f"[FORGE DEBUG] diff bit count: {bin(diff).count('1')}")

    # When the prefix is part of the full info (prefix || expiry),
    # bit k of the prefix corresponds to bit (k+64) of the full 256-bit integer.
    # So we need to shift our step calculations by 64 bits.
    # 
    # IMPORTANT: g is a quadratic residue with order (p-1)/2.
    # So exponents should be reduced modulo (p-1)/2.
    order = (p - 1) // 2
    
    mult = 1
    for k in range(N_BITS):
        if (diff >> k) & 1:
            mb = (base_pref_int >> k) & 1
            sb = (s192 >> k) & 1
            e_bit = mb ^ sb
            # Apply the shift: bit k in prefix is bit (k+64) in full info
            exp = (1 << (k + 64)) % order
            step = pow(g, exp, p)
            if e_bit == 0:
                mult = (mult * step) % p
            else:
                mult = (mult * pow(step, -1, p)) % p

    print(f"[FORGE DEBUG] mult: {mult}")
    
    # Let's also verify by computing the expected admin MAC directly
    # admin_info_int = admin_prefix || expiry as big-endian int
    admin_info_full = admin_prefix + expiry
    admin_info_int = int.from_bytes(admin_info_full, "big")
    base_info_int = int.from_bytes(base_info, "big")
    
    # We know bits 64-255 of s (stored in s192 as bits 0-191)
    # But we don't know bits 0-63 of s
    # However, since expiry is the same, those bits cancel out
    
    # The exponent e = info XOR s
    # e_admin = admin_info XOR s
    # e_base = base_info XOR s
    # e_admin XOR e_base = admin_info XOR base_info (since s XOR s = 0)
    
    exp_diff = admin_info_int ^ base_info_int
    print(f"[FORGE DEBUG] exp_diff (admin_info XOR base_info): {hex(exp_diff)}")
    
    # This should equal diff << 64 since only the prefix differs
    expected_exp_diff = diff << 64
    print(f"[FORGE DEBUG] expected exp_diff (diff << 64): {hex(expected_exp_diff)}")
    print(f"[FORGE DEBUG] match? {exp_diff == expected_exp_diff}")

    base_mac = int_from_hex32(base_mac_hex)

    # base_mac is abs_tag(g^e). Actual representative could be base_mac or p-base_mac.
    cands = []
    for rep in [base_mac, (p - base_mac) % p]:
        val = (rep * mult) % p
        val = abs_tag(val, p)
        cands.append(val.to_bytes(32, "big").hex())

    admin_info_hex = (admin_prefix + expiry).hex()
    return admin_info_hex, cands

def main():
    io = remote("ctf.csd.lol", 2020)
    # First line contains p and g
    first = jrecv(io)
    
    if "p" not in first or "g" not in first:
        raise RuntimeError("Remote did not reveal p/g in first JSON output.")
    
    p = int(first["p"])
    g = int(first["g"])
    print("[+] got p,g")
    
    # Now read the actual "awaiting query" message
    jrecv(io)

    base_user = "A" * 32
    pw = "pw"

    # register base + 192 flip users (once)
    register(io, base_user, pw)
    flip_users = []
    for k in range(N_BITS):
        u = make_username_with_flip(base_user, k)
        if k == 0:  # Debug first flip
            print(f"[DEBUG] base_user: '{base_user}'")
            print(f"[DEBUG] flip_user[0]: '{u}'")
            print(f"[DEBUG] base compress: {compress(base_user).hex()}")
            print(f"[DEBUG] flip compress: {compress(u).hex()}")
            base_int = int.from_bytes(compress(base_user), "big")
            flip_int = int.from_bytes(compress(u), "big")
            print(f"[DEBUG] base_int: {base_int}")
            print(f"[DEBUG] flip_int: {flip_int}")
            print(f"[DEBUG] XOR diff: {base_int ^ flip_int} (should be 1 for k=0)")
        flip_users.append(u)
        register(io, u, pw)

    # recover s low 192 bits
    s192 = recover_s192(io, p, g, base_user, pw, flip_users)
    print("[+] s192 =", hex(s192))

    # get one fresh base token to forge from
    base_info, base_mac = login(io, base_user, pw)

    admin_info, admin_macs = forge_admin(p, g, s192, base_info, base_mac, base_user)
    
    print(f"[DEBUG] admin_info: {admin_info}")
    print(f"[DEBUG] admin_macs: {admin_macs}")
    print(f"[DEBUG] base_info: {base_info}")
    print(f"[DEBUG] base_mac: {base_mac}")

    for mh in admin_macs:
        r = read_admin(io, admin_info, mh)
        if r.get("out") == "data read":
            print("[+] FLAG:", r.get("data"))
            return
        else:
            print(f"[-] Attempt with MAC {mh[:16]}... failed: {r.get('out')}")

    print("[-] forge failed (likely compress bit order mismatch).")

if __name__ == "__main__":
    main()
