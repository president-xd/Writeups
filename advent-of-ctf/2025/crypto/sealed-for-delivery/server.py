#!/usr/bin/env python3
import socket
import subprocess
import sys

PORT = 1337

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', PORT))
s.listen(5)
print(f"Listening on port {PORT}", file=sys.stderr, flush=True)

while True:
    conn, addr = s.accept()
    print(f"Connection from {addr}", file=sys.stderr, flush=True)
    
    # Run chal.py with the connection as stdin/stdout
    proc = subprocess.Popen(
        ['python', '-u', 'chal.py'],
        stdin=conn.makefile('r'),
        stdout=conn.makefile('w'),
        stderr=sys.stderr
    )
    proc.wait()
    
    conn.close()
    print(f"Connection from {addr} closed", file=sys.stderr, flush=True)
