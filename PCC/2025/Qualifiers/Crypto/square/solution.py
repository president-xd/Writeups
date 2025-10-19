#!/usr/bin/env python3
# solution.py
# Connects, fetches blocks, brute-forces A, recovers SECRET(s),
# AND forward-verifies by computing A @ B and comparing to server T blocks.

import socket, sys, re, time
import numpy as np

HOST = sys.argv[1] if len(sys.argv) > 1 else "c1.arena.airoverflow.com"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 56669
TIMEOUT = 8.0

def recv_all(sock, timeout=0.5):
    sock.settimeout(timeout)
    data = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data.decode(errors="ignore")

def sendline(sock, s):
    if isinstance(s, str):
        s = s.encode()
    sock.sendall(s + b"\n")

def parse_blocks(text):
    blocks = []
    pat = re.compile(r"Block\s*\d+\s*:\s*\n\s*\[\s*\[([^\]]+)\]\s*\n\s*\[([^\]]+)\]\s*\]", re.MULTILINE)
    for m in pat.finditer(text):
        r1 = [int(x) for x in re.split(r"\s+", m.group(1).strip()) if x != ""]
        r2 = [int(x) for x in re.split(r"\s+", m.group(2).strip()) if x != ""]
        if len(r1)==2 and len(r2)==2:
            blocks.append(np.array([r1, r2], dtype=int))
    return blocks

def generate_candidates():
    L=[]
    for a in range(-3,4):
        for b in range(-3,4):
            for c in range(-3,4):
                for d in range(-3,4):
                    det = a*d - b*c
                    if det in (1,-1):
                        L.append(np.array([[a,b],[c,d]], dtype=int))
    return L

def int_inv(A):
    a,b = int(A[0,0]), int(A[0,1])
    c,d = int(A[1,0]), int(A[1,1])
    det = a*d - b*c
    adj = np.array([[d, -b], [-c, a]], dtype=int)
    return adj // det

def blocks_from_secret_bytes(secret_bytes):
    arr = np.frombuffer(secret_bytes, dtype=np.uint8)
    return arr.reshape(-1,2,2)

def try_all_and_verify(blocks):
    """Return list of (secret, A) that pass forward verify A @ B == T for all blocks"""
    candidates = generate_candidates()
    valid = []
    for A in candidates:
        invA = int_inv(A)
        recovered = []
        ok = True
        for T in blocks:
            B = invA.dot(T)
            # B must be integers 0..255
            if not (np.all(B >= 0) and np.all(B <= 255)):
                ok = False
                break
            flat = B.reshape(-1)
            # check characters are ascii alnum (same charset used by chal)
            if not all((48 <= v <= 57) or (65 <= v <= 90) or (97 <= v <= 122) for v in flat):
                ok = False
                break
            recovered.extend(int(x) for x in flat)
        if not ok:
            continue
        if len(recovered) != 24:
            continue
        secret = bytes(recovered)
        # forward-verify: split secret into 2x2 blocks and compute A @ B
        B_blocks = blocks_from_secret_bytes(secret)
        forward = [A.dot(B_blocks[i]) for i in range(len(B_blocks))]
        # Compare forward to given blocks exactly
        eq = all(np.array_equal(forward[i], blocks[i]) for i in range(len(blocks)))
        if eq:
            valid.append((secret.decode('ascii'), A.copy()))
    return valid

def main():
    print(f"[+] Connecting to {HOST}:{PORT}")
    s = socket.create_connection((HOST, PORT), timeout=TIMEOUT)
    try:
        intro = recv_all(s, timeout=1.0)
        print(intro, end='')
        sendline(s, "1")  # create new secret
        out = recv_all(s, timeout=1.0)
        print("[+] After create:", out, end='')
        sendline(s, "2")  # get transformed blocks
        out = recv_all(s, timeout=1.0)
        print("[+] Blocks text:\n", out)
        blocks = parse_blocks(out)
        if not blocks:
            print("[-] Failed to parse any blocks. Raw text above.")
            return
        print(f"[+] Parsed {len(blocks)} blocks.")
        valid = try_all_and_verify(blocks)
        if not valid:
            print("[-] No candidate SECRET passed exact forward verification.")
            print("This means either parsing failed, or our candidate-search/charset filter missed a valid A.")
            print("You can paste the block text here if you want me to analyze further.")
            return
        print(f"[+] Found {len(valid)} valid SECRET(s) that exactly recreate the T blocks:")
        for sec, A in valid:
            print("  SECRET:", sec)
            print("  A =")
            print(A)
            print()
        print("[*] If you get one or more SECRETS above, they are mathematically correct.")
        print("Now submit any one of them to the original server (menu option 3).")
        # attempt to submit the first and print server response
        print("[*] Submitting first valid SECRET to server to observe response...")
        sendline(s, "3")
        time.sleep(0.1)
        prompt = recv_all(s, timeout=0.5)
        print("[+] Server prompt after choosing 3:")
        print(prompt, end='')
        sendline(s, valid[0][0])
        time.sleep(0.2)
        resp = recv_all(s, timeout=1.5)
        print("[+] Server response after submission:")
        print(resp)
    finally:
        s.close()

if __name__ == "__main__":
    main()