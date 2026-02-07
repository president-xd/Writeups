#!/usr/bin/env python3
"""
LA CTF - Garbled Circuit Challenge Solver

Vulnerability: Cipher.__init__ uses `iv = get_random_bytes(8)` as a default
argument, which is evaluated ONCE at class definition. ALL AES-CTR ciphers
share the same nonce, making double-encryption just XOR with keystreams.

Attack: XOR the 3 garbled table key-ciphertexts to recover delta (the Free XOR
global offset). Then evaluate normally to get out_zero_key, and compute
out_one_key = out_zero_key XOR delta.
"""

import socket
import struct
import time
import base64
import re
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor

BUF_LEN = 16


def recv_until(s, marker, timeout=15):
    data = b""
    s.settimeout(timeout)
    while marker not in data:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        except socket.timeout:
            break
    return data


def recv_all(s, timeout=5):
    data = b""
    s.settimeout(timeout)
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        except socket.timeout:
            break
    return data


def solve_pow(challenge):
    """Solve redpwn proof of work in pure Python."""
    MOD = (1 << 1279) - 1
    EXP = 1 << 1277

    parts = challenge.split(".")
    d_bytes = base64.b64decode(parts[1])
    d_bytes = b'\x00' * (4 - len(d_bytes)) + d_bytes
    d = struct.unpack(">I", d_bytes)[0]
    x = int.from_bytes(base64.b64decode(parts[2]), "big")

    print(f"PoW difficulty: {d}")
    t0 = time.time()
    for i in range(d):
        x = pow(x, EXP, MOD)
        x ^= 1
        if (i + 1) % 2000 == 0:
            elapsed = time.time() - t0
            eta = elapsed / (i + 1) * (d - i - 1)
            print(f"  {i+1}/{d} ({elapsed:.1f}s, ETA {eta:.1f}s)")

    solution = f"s.{base64.b64encode(x.to_bytes((x.bit_length() + 7) // 8, 'big')).decode()}"
    print(f"PoW solved in {time.time() - t0:.1f}s")
    return solution


def main():
    HOST = "chall.lac.tf"
    PORT = 31182

    print(f"Connecting to {HOST}:{PORT}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    # Read until input prompt, handling optional PoW
    data = recv_until(s, b"fate: ", timeout=15)
    text = data.decode()

    if "proof of work" in text:
        print("[*] PoW detected")
        match = re.search(r'(s\.\S+)', text)
        challenge = match.group(1)
        solution = solve_pow(challenge)

        # Send PoW solution
        s.sendall(solution.encode() + b"\n")

        # Wait for the actual challenge prompt
        data2 = recv_until(s, b"fate: ", timeout=15)
        text += data2.decode()

    # Send choice (0 — doesn't matter, AND with 0 = 0)
    s.sendall(b"0\n")

    # Receive circuit data and answer prompt
    data = recv_until(s, b"mountain: ", timeout=10)
    text = data.decode()
    print(text)

    # Parse output
    lines = text.strip().split('\n')

    wire_lines = []
    table_lines = []
    iv_hex = None

    for line in lines:
        line = line.strip()
        if line.startswith('wire '):
            wire_lines.append(line)
        elif line.startswith('iv:'):
            iv_hex = line.split(': ')[1].strip()
        elif line.startswith('Show me'):
            continue
        else:
            parts = line.split()
            if len(parts) == 2:
                try:
                    bytes.fromhex(parts[0])
                    int(parts[1])
                    table_lines.append(line)
                except (ValueError, IndexError):
                    pass

    # Parse wire 0 and wire 1 labels
    w0_parts = wire_lines[0].split(': ')[1].split()
    w0_key = bytes.fromhex(w0_parts[0])
    w0_ptr = int(w0_parts[1])

    w1_parts = wire_lines[1].split(': ')[1].split()
    w1_key = bytes.fromhex(w1_parts[0])
    w1_ptr = int(w1_parts[1])

    # Parse 3 garbled table entries: [0][1], [1][0], [1][1]
    t01_key = bytes.fromhex(table_lines[0].split()[0])
    t10_key = bytes.fromhex(table_lines[1].split()[0])
    t11_key = bytes.fromhex(table_lines[2].split()[0])
    t01_ptr = int(table_lines[0].split()[1])
    t10_ptr = int(table_lines[1].split()[1])
    t11_ptr = int(table_lines[2].split()[1])

    iv = bytes.fromhex(iv_hex)

    print(f"\n[*] Parsed values:")
    print(f"  w0: key={w0_key.hex()}, ptr={w0_ptr}")
    print(f"  w1: key={w1_key.hex()}, ptr={w1_ptr}")
    print(f"  iv: {iv.hex()}")

    # === ATTACK ===

    # Step 1: Recover delta by XORing all 3 table key ciphertexts
    # Due to shared AES-CTR nonce, the keystream terms cancel out and
    # we're left with: delta = ct_01_key XOR ct_10_key XOR ct_11_key
    delta = strxor(strxor(t01_key, t10_key), t11_key)
    print(f"\n[*] Recovered delta = {delta.hex()}")

    # Step 2: Evaluate circuit normally to get out_zero_key
    # (AND gate with input 0 always outputs 0)
    if w0_ptr == 0 and w1_ptr == 0:
        # GRR3: decrypt zeros
        aes1 = AES.new(w0_key, AES.MODE_CTR, nonce=iv)
        aes2 = AES.new(w1_key, AES.MODE_CTR, nonce=iv)
        out_zero_key = aes1.decrypt(aes2.decrypt(bytes(BUF_LEN)))
    else:
        # Use the table entry at our pointer position
        table = {(0, 1): t01_key, (1, 0): t10_key, (1, 1): t11_key}
        row_key = table[(w0_ptr, w1_ptr)]
        aes1 = AES.new(w0_key, AES.MODE_CTR, nonce=iv)
        aes2 = AES.new(w1_key, AES.MODE_CTR, nonce=iv)
        out_zero_key = aes1.decrypt(aes2.decrypt(row_key))

    print(f"[*] out_zero_key = {out_zero_key.hex()}")

    # Step 3: Compute out_one_key = out_zero_key XOR delta
    out_one_key = strxor(out_zero_key, delta)
    print(f"[*] out_one_key = {out_one_key.hex()}")

    # Send the answer
    s.sendall(out_one_key.hex().encode() + b"\n")

    # Receive flag
    response = recv_all(s, timeout=5)
    print(f"\n{response.decode()}")

    s.close()


if __name__ == "__main__":
    main()
