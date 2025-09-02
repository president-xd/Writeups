#!/usr/bin/env python3
import socket
import re
import hashlib

HOST = "52.50.32.75"
PORT = 31250

# Curve order of Ed25519 base point (same as code's `l`)
L = 2**252 + 27742317777372353535851937790883648493

# ===== Broken hash exactly as in the challenge =====
def H(m: bytes) -> bytes:
    out = b""
    for i in range(4):
        out += hashlib.md5(m + bytes([i])).digest()
    return out  # 64 bytes

def Hint(m: bytes) -> int:
    # The code sums bits little-endian; this equals int.from_bytes( H(m), "little" )
    return int.from_bytes(H(m), "little")

# ===== Known 128-byte MD5-collision pair (Marc Stevens, 2009) =====
# Both have md5 = d320b6433d8ebc1ac65711705721c2e1
HEX1 = (
"4F64656420476F6C"
"6472656963680A4F"
"64656420476F6C64"
"72656963680A4F64"
"656420476F6C6472"
"656963680A4F6465"
"6420476F"
"D8050D00"
"19BB9318924CAA96"
"DCE35CB835B349E1"
"44E98C50C22CF461"
"244A4064BF1AFAEC"
"C5820D428AD38D6B"
"EC89A5AD51E29063"
"DD79B16CF67C1297"
"8647F5AF123DE3AC"
"F844085CD025B956"
)

HEX2 = (
"4E65616C204B6F62"
"6C69747A0A4E6561"
"6C204B6F626C6974"
"7A0A4E65616C204B"
"6F626C69747A0A4E"
"65616C204B6F626C"
"69747A0A"
"75B80E00"
"35F3D2C909AF1BAD"
"DCE35CB835B349E1"
"44E88C50C22CF461"
"244A40E4BF1AFAEC"
"C5820D428AD38D6B"
"EC89A5AD51E29063"
"DD79B16CF6FC1197"
"8647F5AF123DE3AC"
"F84408DCD025B956"
)

M1 = bytes.fromhex(HEX1)
M2 = bytes.fromhex(HEX2)

assert len(M1) == len(M2) == 128
assert hashlib.md5(M1).hexdigest() == hashlib.md5(M2).hexdigest() == "d320b6433d8ebc1ac65711705721c2e1"

MESSAGE = b"gimme the flag"  # forbidden message on server

def recv_until(sock, marker: bytes) -> bytes:
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Socket closed")
        data += chunk
    return data

def send_line(sock, s: str):
    sock.sendall(s.encode() + b"\n")

def parse_pk_line(blob: bytes) -> bytes:
    # line looks like: b'pk (hex): <hex>\n'
    m = re.search(rb"pk \(hex\):\s*([0-9a-fA-F]+)", blob)
    if not m:
        raise ValueError("Could not find pk hex")
    return bytes.fromhex(m.group(1).decode())

def parse_sig_from_chunk(blob: bytes) -> bytes:
    # The signer prints the signature hex alone on its own line.
    # Grab the last hex-looking line with length >= 128 hex chars (64 bytes).
    lines = blob.strip().splitlines()
    for line in reversed(lines):
        line = line.strip()
        if re.fullmatch(rb"[0-9a-fA-F]{128}", line):
            return bytes.fromhex(line.decode())
    raise ValueError("Could not find signature hex")

def main():
    with socket.create_connection((HOST, PORT), timeout=10) as s:
        # Read greeting and pk
        data = recv_until(s, b"command:")
        pk = parse_pk_line(data)              # 32 bytes
        # --- 1) get signature on M1 ---
        send_line(s, "sign")
        recv_until(s, b"message (hex):")
        send_line(s, M1.hex())
        chunk = recv_until(s, b"command:")
        sig1 = parse_sig_from_chunk(chunk)
        # --- 2) get signature on M2 ---
        send_line(s, "sign")
        recv_until(s, b"message (hex):")
        send_line(s, M2.hex())
        chunk = recv_until(s, b"command:")
        sig2 = parse_sig_from_chunk(chunk)

        # Parse R||S (little-endian S)
        R1, S1_le = sig1[:32], sig1[32:]
        R2, S2_le = sig2[:32], sig2[32:]

        if R1 != R2:
            raise RuntimeError("R mismatch — collision pair failed (shouldn't happen).")

        R = R1
        S1 = int.from_bytes(S1_le, "little")
        S2 = int.from_bytes(S2_le, "little")

        # Compute the scalars h1, h2, ht exactly as verifier does
        h1 = Hint(R + pk + M1) % L
        h2 = Hint(R + pk + M2) % L
        ht = Hint(R + pk + MESSAGE) % L

        # Recover 'a' and 'r'
        denom = (h1 - h2) % L
        if denom == 0:
            raise RuntimeError("Unexpected: h1 == h2 mod l")
        inv_denom = pow(denom, -1, L)  # Python 3.8+: modular inverse
        a = ((S1 - S2) % L) * inv_denom % L
        r = (S1 - (h1 * a) % L) % L

        # Forge signature on MESSAGE with the same R
        S_star = (r + (ht * a) % L) % L
        forged = R + S_star.to_bytes(32, "little")

        # Submit forged signature for verification
        send_line(s, "verify")
        recv_until(s, b"signature (hex):")
        send_line(s, forged.hex())

        # Read result (should print the flag and exit)
        out = s.recv(4096)
        print(out.decode(errors="ignore"), end="")

if __name__ == "__main__":
    main()
