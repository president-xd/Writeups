#!/usr/bin/env python3
from pwn import remote
from Crypto.Util.number import bytes_to_long, long_to_bytes
from math import gcd
import sys
import time

K = 0x13373           # same k as in the challenge
NUM_QUERIES = 12      # how many base_keys to collect
SEARCH_RADIUS = 600   # seconds around our local time to search for nonce


# ------------------ inversion of __gen_key ------------------ #

def invert_key(keystream_int: int) -> int:
    """
    Invert __gen_key to recover base_key.

    Original key schedule:

        key = base_key
        kh = key >> 25
        kl = key & 0x1ffffff
        tmp = []
        for __ in range(10):
            for _ in range(25):
                kh, kl = kl, kh ^ kl
            tmp.append(kh << 25 | kl)
        new_key = 0
        for i in range(10):
            new_key = (new_key << 50) | tmp[i]

    Important: each 25-step mixing uses the *current* (kh, kl) and
    appends one 50-bit word to tmp. That means tmp[0] comes from
    the state *after* the first 25 iterations.

    We only need to invert the *first* block, which is stored in
    the high 50 bits of new_key. The later blocks do not affect
    the original base_key reconstruction.
    """
    # Extract the first 50-bit chunk: it corresponds to tmp[0]
    tmp0 = keystream_int >> (50 * 9)
    kh = tmp0 >> 25
    kl = tmp0 & ((1 << 25) - 1)

    # Invert the 25 rounds of:
    #   for _ in range(25):
    #       kh, kl = kl, kh ^ kl
    #
    # Forward:
    #   new_kh = kl
    #   new_kl = kh ^ kl
    #
    # Inverse:
    #   old_kh = (kh ^ kl)
    #   old_kl = kh
    for _ in range(25):
        kh, kl = kh ^ kl, kh

    base_key = (kh << 25) | kl
    return base_key


# ------------------ CRT helper ------------------ #

def crt_pair(a1, n1, a2, n2):
    """
    Solve:
        x ≡ a1 (mod n1)
        x ≡ a2 (mod n2)

    Return (x mod lcm(n1, n2), lcm(n1, n2)) or (None, None) if inconsistent.
    """
    g = gcd(n1, n2)
    if (a2 - a1) % g != 0:
        return None, None

    # Reduced moduli
    n1p, n2p = n1 // g, n2 // g

    # Extended GCD to get inverse of n1p mod n2p
    def eg(a, b):
        if b == 0:
            return 1, 0, a
        x, y, g2 = eg(b, a % b)
        return y, x - (a // b) * y, g2

    inv, _, _ = eg(n1p, n2p)
    inv %= n2p

    t = ((a2 - a1) // g * inv) % n2p
    x = a1 + n1 * t
    lcm = n1 * n2p
    return x % lcm, lcm


def recover_generator_for_nonce(base_keys, nonce_guess, k=K):
    """
    Given base_keys[i] = G mod (k * (nonce + i)),
    and a guessed nonce, reconstruct G using CRT.

    For a wrong nonce, we still get some integer G, but it will not
    correspond to a nice ASCII "HTB{...}" flag.
    """
    a = base_keys[0]
    n = k * (nonce_guess + 0)

    for i in range(1, len(base_keys)):
        Mi = k * (nonce_guess + i)
        ai = base_keys[i] % Mi
        a, n = crt_pair(a, n, ai, Mi)
        if a is None:
            return None  # inconsistent, but this rarely happens

    # Generator is smaller than the product of moduli, so we can just take 'a'
    return a


# ------------------ flag candidate checks ------------------ #

def looks_like_flag(b: bytes) -> bool:
    """
    Check that bytes look like a plausible HTB flag.
    """
    try:
        s = b.decode()
    except UnicodeDecodeError:
        return False

    if not (s.startswith("HTB{") and s.endswith("}")):
        return False

    # Ensure all characters are printable ASCII
    if not all(32 <= c < 127 for c in b):
        return False

    # Reasonable length bounds
    if not (10 <= len(b) <= 100):
        return False

    return True


def find_flag_from_basekeys(base_keys, time_guess, radius, k=K):
    """
    Scan nonces in [time_guess - radius, time_guess + radius].
    For each, reconstruct generator and check if it decodes to an HTB flag.
    """
    for dt in range(-radius, radius + 1):
        nonce_guess = time_guess + dt
        G = recover_generator_for_nonce(base_keys, nonce_guess, k)
        if G is None:
            continue

        candidate_bytes = long_to_bytes(G)
        if looks_like_flag(candidate_bytes):
            return nonce_guess, candidate_bytes.decode()

    return None, None


# ------------------ interact with remote ------------------ #

def collect_base_keys(io, num_queries=NUM_QUERIES):
    """
    Talk to the remote service, send chosen plaintexts,
    recover keystreams and invert to base_keys.
    """
    base_keys = []

    # Consume initial banner and first prompt
    io.recvuntil(b"quit): ")

    plaintext = b"A" * 64  # arbitrary fixed message

    for i in range(num_queries):
        # Send plaintext
        io.sendline(plaintext)

        # Read "Encrypted Message: <hex>"
        line = io.recvline().strip()
        if b"Encrypted Message:" not in line:
            raise RuntimeError(f"Unexpected line: {line!r}")

        hex_ct = line.split(b":")[1].strip()
        ct = bytes.fromhex(hex_ct.decode())

        # msg_int is what the server used internally
        msg_int = bytes_to_long(plaintext)
        ct_int = bytes_to_long(ct)

        key_int = msg_int ^ ct_int
        base_key = invert_key(key_int)
        base_keys.append(base_key)

        # Consume the next prompt before next iteration (except maybe last)
        if i != num_queries - 1:
            io.recvuntil(b"quit): ")

    return base_keys


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} HOST PORT")
        return

    host = sys.argv[1]
    port = int(sys.argv[2])

    io = remote(host, port)

    try:
        base_keys = collect_base_keys(io, NUM_QUERIES)
        print("[*] Collected base_keys:")
        for i, bk in enumerate(base_keys):
            print(f"    base_keys[{i}] = {bk}")

        # Our best guess at server time is our local time *now*
        time_guess = int(time.time())
        print(f"[*] Local epoch guess: {time_guess}")

        nonce, flag = find_flag_from_basekeys(base_keys, time_guess, SEARCH_RADIUS)
        if flag is None:
            print("[!] Failed to recover flag. You can try increasing SEARCH_RADIUS or NUM_QUERIES.")
        else:
            print(f"[+] Found nonce: {nonce}")
            print(f"[+] Flag: {flag}")

    finally:
        io.close()


if __name__ == "__main__":
    main()
