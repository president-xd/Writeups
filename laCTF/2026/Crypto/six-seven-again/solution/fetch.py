#!/usr/bin/env python3
# Fetch challenge data from server (handles PoW)
import socket, subprocess, re, sys

HOST = 'chall.lac.tf'
PORT = 31181

def recv_until(sock, marker, timeout=30):
    data = b''
    sock.settimeout(timeout)
    while marker not in data:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        except socket.timeout:
            break
    return data

print("[*] Connecting...", file=sys.stderr)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(30)
s.connect((HOST, PORT))

data = recv_until(s, b'solution:')
text = data.decode()
print(f"[*] Got PoW challenge", file=sys.stderr)

pow_match = re.search(r'(curl -sSfL https://pwn\.red/pow \| sh -s \S+)', text)
if pow_match:
    pow_cmd = pow_match.group(1)
    print(f"[*] Solving PoW...", file=sys.stderr)
    result = subprocess.run(['bash', '-c', pow_cmd], capture_output=True, text=True, timeout=120)
    pow_solution = result.stdout.strip()
    print(f"[*] PoW solved: {pow_solution[:30]}...", file=sys.stderr)
    s.sendall((pow_solution + '\n').encode())

# Read challenge
data = recv_until(s, b'\n', timeout=15)
data += recv_until(s, b'\n', timeout=15)
s.close()

text = data.decode().strip()
print(f"[*] Got challenge data", file=sys.stderr)

for line in text.strip().split('\n'):
    line = line.strip()
    if line.startswith('n=') or line.startswith('c='):
        print(line)

print("[*] Saved to stdout", file=sys.stderr)
