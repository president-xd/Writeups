#!/usr/bin/env python3
import socket
import re
import json
from math import isqrt
from hashlib import sha256

from Crypto.Cipher import AES  # pycryptodome

HOST = "tcp.flagyard.com"   # <-- put challenge host here
PORT = 24044           # <-- put challenge port here

FLAG_PREFIX = b"BHFlag"   # adjust if the CTF uses a different prefix


def rational_reconstruct(a: int, m: int):
    """
    Recover (n, d) s.t. a ≡ n * d^{-1} (mod m) and
    |n|, |d| <= sqrt((m-1)/2).
    """
    B = isqrt((m - 1) // 2)

    r0, r1 = m, a
    s0, s1 = 1, 0
    t0, t1 = 0, 1

    # r_i = s_i * m + t_i * a
    while abs(r1) > B:
        q = r0 // r1
        r0, r1 = r1, r0 - q * r1
        s0, s1 = s1, s0 - q * s1
        t0, t1 = t1, t0 - q * t1

    n, d = r1, t1
    if d == 0:
        raise ValueError("No reconstruction (denominator zero)")

    if d < 0:
        n, d = -n, -d

    if abs(n) <= B and abs(d) <= B and (a * d - n) % m == 0:
        return n, d

    raise ValueError("No valid rational reconstruction")


def get_transcript():
    """Connect to the nc instance and grab its whole output."""
    s = socket.create_connection((HOST, PORT))
    chunks = []
    while True:
        data = s.recv(4096)
        if not data:
            break
        chunks.append(data)
    s.close()
    return b"".join(chunks)


def solve_instance():
    transcript = get_transcript().decode(errors="ignore")
    # Uncomment if you want to see the banner / debug:
    # print(transcript)

    # Extract the JSON after "Aaron -> Bobby:"
    m = re.search(r"Aaron -> Bobby:\s*(\{.*\})", transcript)
    if not m:
        raise RuntimeError("Could not find Aaron packet in transcript")

    packet_str = m.group(1)
    packet = json.loads(packet_str)

    p = int(packet["p"])
    C1 = int(packet["C1"])
    ct = bytes.fromhex(packet["flag"])

    # 1) Rational reconstruction: C1 ≡ k_red * r_red^{-1} (mod p)
    k_red, r_red = rational_reconstruct(C1, p)

    # Ensure denominator positive
    if r_red < 0:
        k_red, r_red = -k_red, -r_red

    print(f"[+] Reconstructed reduced ratio k'/r' with k' bitlen={k_red.bit_length()}, r' bitlen={r_red.bit_length()}")

    # 2) Brute-force the small gcd factor d (≈ mask < 2^24)
    MAX_D = 1 << 24

    for d in range(1, MAX_D):
        k_candidate = d * k_red
        # k must fit in 128 bits
        if k_candidate >= (1 << 128):
            break

        k_bytes = k_candidate.to_bytes(16, "big")
        aes_key = sha256(k_bytes).digest()
        aes = AES.new(aes_key, AES.MODE_ECB)

        # Decrypt first block; cheap to test
        pt_first_block = aes.decrypt(ct[:16])

        if not pt_first_block.startswith(FLAG_PREFIX):
            continue

        # Looks good — decrypt full ciphertext
        pt_full = aes.decrypt(ct)
        print(f"[+] Found candidate d = {d}")
        print(f"[+] k = {k_candidate}")
        print("[+] Plaintext (raw bytes):", pt_full)

        # Try to extract the flag as ASCII
        try:
            txt = pt_full.decode(errors="ignore")
        except Exception:
            txt = repr(pt_full)

        print("[+] As text:", txt)
        return

    print("[-] Failed to find flag; maybe wrong prefix or bounds?")


if __name__ == "__main__":
    solve_instance()
