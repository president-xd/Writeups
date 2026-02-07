#!/usr/bin/env python3
"""
CandlesCake Secure Ordering — Solve Script

Attack: g(x,a,b) = x^3 + a*x^2 + b*x mod P = 0 when x ≡ 0 (mod P).
RSA signature of 0 is 0. Forge by finding printable suffix that makes x ≡ 0 mod P.
"""
import ssl
import socket
import sys
import time
import random

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF61
B = b"I authorize the transaction:\n"
PAD_BYTE = (len(B) + 48) & 0xFF  # 77 = 0x4d
R128 = 159  # 2^128 mod P  (since P = 2^128 - 159)

PRINTABLE = list(range(32, 127))


def pad(x):
    return x + bytes([len(x) & 255])


def bytes_to_long(b):
    return int.from_bytes(b, 'big')


def find_printable_suffix():
    """Find 48-byte printable suffix so bytes_to_long(pad(B+suffix)) ≡ 0 (mod P)."""
    B_int = bytes_to_long(B)

    # M = B_int * 256^49 + suffix_int * 256 + PAD_BYTE  ≡ 0 (mod P)
    # suffix_int ≡ -(B_int * 256^49 + PAD_BYTE) * 256^{-1} (mod P)
    inv256 = pow(256, P - 2, P)
    target = (-(B_int * pow(256, 49, P) + PAD_BYTE) * inv256) % P

    # suffix = head(32 bytes, printable) + tail(16 bytes, must be printable)
    # suffix_int = head_int * 2^128 + tail_int
    # tail_int = (target - head_int * 159) mod P
    shift = R128  # 159

    print(f"Target residue: {target}", flush=True)
    print("Searching (random 32-byte heads)...", flush=True)
    t_start = time.time()

    choices = random.choices  # local ref for speed
    count = 0
    while True:
        head_bytes = bytes(choices(PRINTABLE, k=32))
        head_mod = int.from_bytes(head_bytes, 'big') % P
        tail = (target - head_mod * shift) % P
        count += 1

        # Quick filter: check LSB first (63% rejected instantly)
        if (tail & 0xFF) < 32 or (tail & 0xFF) > 126:
            if count % 2_000_000 == 0:
                print(f"  {count:,} tries  ({time.time()-t_start:.1f}s)", flush=True)
            continue

        # Full check on all 16 bytes
        tail_bytes = tail.to_bytes(16, 'big')
        if all(32 <= b <= 126 for b in tail_bytes):
            elapsed = time.time() - t_start
            print(f"Found after {count:,} attempts ({elapsed:.1f}s)")
            return head_bytes + tail_bytes

        if count % 2_000_000 == 0:
            print(f"  {count:,} tries  ({time.time()-t_start:.1f}s)", flush=True)


def solve():
    suffix = find_printable_suffix()
    if suffix is None:
        sys.exit(1)

    # Verify locally
    x = int.from_bytes(pad(B + suffix), 'big')
    assert x % P == 0, f"FAIL: x mod P = {x % P}"
    print(f"Verified: x mod P = 0 => g(x,a,b) = 0 => sig = 0")
    print(f"Suffix (ascii): {suffix.decode('ascii')}")

    # ---- Connect to server ----
    host = "candles.ctf.prgy.in"
    port = 1337

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    print(f"\nConnecting to {host}:{port} (TLS)...", flush=True)
    raw = socket.create_connection((host, port), timeout=30)
    conn = ctx.wrap_socket(raw, server_hostname=host)
    conn.settimeout(10)

    def recv_until(marker):
        buf = b""
        while marker not in buf:
            try:
                chunk = conn.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
        return buf.decode(errors='replace')

    def sendline(msg):
        conn.sendall((msg + "\n").encode())

    # Banner + menu
    resp = recv_until(b"> ")
    print(resp, end='', flush=True)

    # Option 2: Execute transaction
    sendline("2")
    resp = recv_until(b"Suffix:")
    print(resp, flush=True)

    # Send crafted suffix
    sendline(suffix.decode('ascii'))
    resp = recv_until(b"Signature:")
    print(resp, flush=True)

    # Signature = 0 (because g(x,a,b)=0 and 0^d mod n = 0)
    sendline("0")

    # Read flag
    time.sleep(1)
    buf = b""
    try:
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
    except (socket.timeout, ssl.SSLError, OSError):
        pass

    print(buf.decode(errors='replace'))
    conn.close()


if __name__ == "__main__":
    solve()
