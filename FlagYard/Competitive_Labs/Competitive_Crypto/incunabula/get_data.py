#!/usr/bin/env python3
"""
Fetch challenge data from server and save for C solver.
"""
import socket

host = "tcp.flagyard.com"
port = 23261
# tcp.flagyard.com:23261

print("Connecting...", file=__import__('sys').stderr)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(30)
sock.connect((host, port))

data = b""
while True:
    try:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    except socket.timeout:
        break
sock.close()

text = data.decode()
lines = text.strip().split('\n')
params = eval(lines[0])
ciphertexts = eval(lines[1])

# Output for C program
print(params['p'])
for r in params['roots']:
    print(r)
print(len(ciphertexts))
for ct in ciphertexts:
    print(ct)
