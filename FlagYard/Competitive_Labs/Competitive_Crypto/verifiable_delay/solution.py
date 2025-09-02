#!/usr/bin/env python3
import re
import socket
import sys
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "52.50.32.75"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 31250
TIMEOUT = 10.0

INT_RE = re.compile(r"(-?\d+)")

def recv_all_until(sock, must_have:list, timeout=TIMEOUT):
    """Read until all substrings in `must_have` appear (in any order) or timeout."""
    sock.settimeout(timeout)
    buf = ""
    start = time.time()
    while True:
        try:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk.decode(errors="ignore")
            if all(x in buf for x in must_have):
                break
        except socket.timeout:
            # keep looping until timeout window exceeded
            pass
        if time.time() - start > timeout:
            break
    return buf

def find_int_after(label, blob):
    m = re.search(rf"{re.escape(label)}\s*=\s*([0-9]+)", blob)
    if not m:
        m = re.search(rf"{re.escape(label)}\s*([0-9]+)", blob)  # fallback
    if not m:
        # Last-ditch: first big int after label
        idx = blob.find(label)
        if idx >= 0:
            tail = blob[idx:]
            m2 = INT_RE.search(tail)
            if m2:
                return int(m2.group(1))
        raise ValueError(f"Could not parse integer after '{label}'")
    return int(m.group(1))

def main():
    with socket.create_connection((HOST, PORT), timeout=TIMEOUT) as s:
        # 1) Read the opening two lines: modulus and result
        blob = recv_all_until(s, ["modulus is", "in Z_n"], timeout=TIMEOUT)
        # Try to read a bit more in case of buffering
        s.settimeout(0.2)
        try:
            blob += s.recv(65536).decode(errors="ignore")
        except Exception:
            pass

        # Parse n and result
        try:
            n = find_int_after("modulus is", blob)
        except Exception:
            # Alternative pattern like "modulus is {n}\n"
            m = re.search(r"modulus is\s+([0-9]+)", blob)
            if not m:
                raise
            n = int(m.group(1))

        # result line may say: "in Z_n, g^(2^(2^256)) == {result}"
        m = re.search(r"==\s*([0-9]+)", blob)
        if not m:
            raise ValueError("Could not parse 'result'")
        result = int(m.group(1))

        # 2) Choose h = -result mod n (i.e., n - result), avoiding the "obvious proofs" check h != result
        h = (n - result) % n
        # Ensure 1 < h < n-1
        if not (1 < h < n - 1):
            # extremely unlikely; simple fallback tweak
            h = (n - result - 1) % n
            if not (1 < h < n - 1) or h == result:
                raise RuntimeError("Failed to choose a valid h")

        # Send h
        s.sendall((str(h) + "\n").encode())

        # 3) Read challenge l and the leaked correct proof
        blob2 = recv_all_until(s, ["my challenge is", "the correct proof is"], timeout=TIMEOUT)
        # Parse l and proof
        l = find_int_after("my challenge is", blob2)
        proof = find_int_after("the correct proof is", blob2)

        # 4) Pick pi = -proof mod n (works for odd prime l, which is the case with overwhelming probability)
        pi = (n - proof) % n
        # Pass basic constraints
        if not (1 < pi < n - 1) or pi == proof:
            # Very unlikely; try another harmless tweak that preserves (-1)^l factor when l is odd
            pi = (n - proof) % n
            if not (1 < pi < n - 1) or pi == proof:
                raise RuntimeError("Failed to choose a valid pi")

        # Send pi
        s.sendall((str(pi) + "\n").encode())

        # 5) Read the rest, print the flag line if present
        tail = ""
        s.settimeout(2.0)
        try:
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                tail += chunk.decode(errors="ignore")
        except Exception:
            pass

        # Show server response; extract flag if present
        print(tail.strip())
        mflag = re.search(r"(FlagY\{[^\n}]*\})", tail)
        if mflag:
            print(mflag.group(1))

if __name__ == "__main__":
    main()
