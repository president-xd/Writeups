#!/usr/bin/env python3
import socket
import sys
import re
import math

HOST = "chal.sunshinectf.games"
PORT = 25403

# Known-plaintext (first 16 bytes only) -> "Greetings, Earth"
KNOWN16 = b"Greetings, Earth"

HEX_RE = re.compile(r"^[0-9a-f]+\s*$", re.IGNORECASE)

def readline(sock, timeout=10.0):
    sock.settimeout(timeout)
    data = bytearray()
    while True:
        ch = sock.recv(1)
        if not ch:
            # connection closed
            break
        data += ch
        if ch == b"\n":
            break
    return bytes(data)

def recv_hex_lines(sock, n_lines):
    """Read and return exactly n_lines of hex strings (stripped)."""
    lines = []
    while len(lines) < n_lines:
        raw = readline(sock)
        if not raw:
            break
        s = raw.decode("utf-8", "ignore").strip()
        if HEX_RE.match(s):
            lines.append(s)
    return lines

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def main():
    print(f"[+] Connecting to {HOST}:{PORT} ...", file=sys.stderr)
    with socket.create_connection((HOST, PORT)) as sock:
        # Grab the first hex line to learn message length & first keystream block
        first_hex = None
        while first_hex is None:
            line = readline(sock)
            if not line:
                print("[-] Connection closed before any ciphertext!", file=sys.stderr)
                sys.exit(1)
            s = line.decode("utf-8", "ignore").strip()
            if HEX_RE.match(s):
                first_hex = s
                break

        ct0 = bytes.fromhex(first_hex)
        msg_len = len(ct0)
        blocks = math.ceil(msg_len / 16)
        print(f"[+] Got first ciphertext line ({msg_len} bytes, {blocks} blocks).", file=sys.stderr)

        # We need a total of `blocks` lines to recover S[0..blocks-1].
        # We already have the first line; read (blocks-1) more.
        more_hex = recv_hex_lines(sock, blocks - 1)
        if len(more_hex) != blocks - 1:
            print("[-] Did not receive enough ciphertext lines to reconstruct keystream.", file=sys.stderr)
            sys.exit(1)

        # Collect the ciphertext lines (as bytes)
        cts = [ct0] + [bytes.fromhex(h) for h in more_hex]

        # Recover keystream blocks S[i] using the first block from line i:
        # S[i] = CT_line_i_block0 ^ KNOWN16
        keystream_blocks = []
        for i in range(blocks):
            ct_i = cts[i]
            if len(ct_i) < 16:
                print("[-] Unexpected short ciphertext line.", file=sys.stderr)
                sys.exit(1)
            s_i = xor_bytes(ct_i[:16], KNOWN16)
            keystream_blocks.append(s_i)

        # Decrypt the whole message using line 0's ciphertext and recovered S[0..]
        pt = bytearray()
        for b in range(blocks):
            start = 16 * b
            end = min(start + 16, msg_len)
            ct_block = ct0[start:end]
            ks_block = keystream_blocks[b][: (end - start)]
            pt.extend(xor_bytes(ct_block, ks_block))

        try:
            plaintext = pt.decode("utf-8")
        except UnicodeDecodeError:
            plaintext = pt.decode("latin-1")

        print("[+] Decrypted MESSAGE:\n")
        print(plaintext)

if __name__ == "__main__":
    main()
