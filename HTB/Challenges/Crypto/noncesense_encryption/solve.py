import socket
import time
from math import gcd


def recv_until(sock, marker):
    """Receive data until marker is found"""
    data = b''
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def bytes_to_long(b):
    return int.from_bytes(b, 'big')


def long_to_bytes(n):
    if n == 0:
        return b'\x00'
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')


def forward_gen_key(base_key):
    """Reproduce __gen_key to verify recovery"""
    kh = base_key >> 25
    kl = base_key & 0x1ffffff
    tmp = []
    for __ in range(10):
        for _ in range(25):
            kh, kl = kl, kh ^ kl
        tmp.append(kh << 25 | kl)
    new_key = 0
    for i in range(10):
        new_key = (new_key << 50) | tmp[i]
    return new_key


def recover_base_key(generated_key):
    """Invert __gen_key: extract tmp[0] and invert 25 Fibonacci-XOR steps"""
    mask50 = (1 << 50) - 1
    mask25 = (1 << 25) - 1

    # tmp[0] is the top 50 bits of the 500-bit key
    tmp0 = (generated_key >> 450) & mask50

    kh = (tmp0 >> 25) & mask25
    kl = tmp0 & mask25

    # Invert 25 steps of: (kh, kl) -> (kl, kh ^ kl)
    # Inverse step: (a, b) -> (b ^ a, a)
    for _ in range(25):
        kh, kl = kl ^ kh, kh

    return kh << 25 | kl


def crt_combine(r1, m1, r2, m2):
    """Combine two congruences: x ≡ r1 (mod m1), x ≡ r2 (mod m2)"""
    g = gcd(m1, m2)
    if (r1 - r2) % g != 0:
        return None, None  # Inconsistent

    lcm = m1 * m2 // g
    m1_g = m1 // g
    m2_g = m2 // g
    diff = (r2 - r1) // g

    try:
        inv = pow(m1_g, -1, m2_g)
    except ValueError:
        return None, None

    t = (inv * diff) % m2_g
    r = (r1 + m1 * t) % lcm
    return r, lcm


def solve():
    HOST = '154.57.164.83'
    PORT = 31614
    k = 0x13373

    t_before = int(time.time())

    print(f"[*] Connecting to {HOST}:{PORT}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(15)
    sock.connect((HOST, PORT))

    t_after = int(time.time())
    print(f"[*] Connected. Time range: {t_before} - {t_after}")

    # Read banner and first prompt
    recv_until(sock, b"quit): ")

    n_queries = 20
    generated_keys = []

    print(f"[*] Sending {n_queries} empty-string queries...")
    for i in range(n_queries):
        sock.sendall(b'\n')  # Empty message → msg = 0 → ciphertext = key
        response = recv_until(sock, b"quit): ")

        text = response.decode(errors='replace')
        idx = text.find("Encrypted Message: ")
        if idx == -1:
            print(f"  [!] Query {i}: Failed to find encrypted message")
            print(f"      Response: {text[:200]}")
            continue

        hex_start = idx + len("Encrypted Message: ")
        hex_end = text.find('\n', hex_start)
        if hex_end == -1:
            hex_end = text.find('\r', hex_start)
        hex_ct = text[hex_start:hex_end].strip()

        ct_bytes = bytes.fromhex(hex_ct)
        gen_key = bytes_to_long(ct_bytes)
        generated_keys.append(gen_key)

    # Send exit
    sock.sendall(b'exit\n')
    sock.close()
    print(f"[*] Collected {len(generated_keys)} generated keys")

    if len(generated_keys) < 2:
        print("[!] Not enough keys collected. Aborting.")
        return

    # Recover base keys and verify
    base_keys = []
    for i, gk in enumerate(generated_keys):
        bk = recover_base_key(gk)
        # Verify by re-generating and comparing
        if forward_gen_key(bk) != gk:
            print(f"  [!] WARNING: base key recovery failed for query {i}")
            print(f"      Generated key: {hex(gk)}")
            print(f"      Recovered base key: {hex(bk)}")
            print(f"      Re-generated key:   {hex(forward_gen_key(bk))}")
        base_keys.append(bk)

    print(f"[*] Recovered {len(base_keys)} base keys")
    print(f"[*] Base keys (first 5): {[hex(bk) for bk in base_keys[:5]]}")

    # Consistency check: all base_keys mod k should equal generator mod k
    residues_mod_k = set(bk % k for bk in base_keys)
    print(f"[*] Distinct residues mod k: {len(residues_mod_k)} (should be 1)")
    if len(residues_mod_k) > 1:
        print(f"    Values: {[hex(r) for r in residues_mod_k]}")

    # Try nonce values around connection time
    search_range = range(t_before - 120, t_after + 120)
    print(f"[*] Searching nonce range: {t_before - 120} to {t_after + 120} ({len(search_range)} candidates)")

    for nonce in search_range:
        # CRT: generator ≡ base_keys[i] (mod (nonce + i) * k)
        r, m = base_keys[0], (nonce + 0) * k
        ok = True

        for i in range(1, len(base_keys)):
            mod_i = (nonce + i) * k
            r, m = crt_combine(r, m, base_keys[i], mod_i)
            if r is None:
                ok = False
                break

        if not ok:
            continue

        # Try to decode as flag
        try:
            flag_bytes = long_to_bytes(r)
            flag_str = flag_bytes.decode('ascii', errors='ignore')
            if 'HTB{' in flag_str:
                print(f"\n[+] FOUND FLAG!")
                print(f"[+] Nonce: {nonce}")
                print(f"[+] Flag: {flag_str}")
                return True
        except Exception:
            continue

    print("[!] Failed to find flag in search range")
    return False


if __name__ == '__main__':
    solve()
