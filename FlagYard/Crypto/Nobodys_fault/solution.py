#!/usr/bin/env python3
"""
Exploit script for the vulnerable RSA signature service.

The remote service exposes three primitives:

1. Sign a message: given an arbitrary message, it returns sig = sha256(msg)^d mod p, where
   d = e^{-1} (mod p-1) and the signature is taken modulo p instead of n = p*q.  For each
   signed message (msg, sig) we have sig^e ≡ sha256(msg) (mod p).  Collecting two or more
   such relations and taking the greatest common divisor of sig^e - h across pairs yields
   the prime factor p.

2. Encrypt a message: given a message interpreted as an integer, it returns enc = msg^e mod q.
   Likewise, for each encryption pair (msg, enc) we have msg^e ≡ enc (mod q), so q divides
   msg^e - enc.  Taking GCDs of these differences leaks q.

3. Verify a signature: checks whether sig^e mod n equals the SHA‑256 hash of the provided message.
   If the check succeeds and the message equals the magic string give_me_flag, the service
   returns the flag.

By abusing the two flawed primitives to recover both RSA primes p and q, we can compute
n = p*q and the private exponent d = e^{-1} (mod (p-1)*(q-1)).  We then forge a valid
signature for the message b'give_me_flag' and submit it to the verify routine to retrieve the
flag.
"""

import math
import random
import socket
import string
from hashlib import sha256
from typing import List, Tuple

# Helper routines to avoid external dependencies
def bytes_to_long(b: bytes) -> int:
    return int.from_bytes(b, 'big')

def long_to_bytes(n: int) -> bytes:
    if n == 0:
        return b'\x00'
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, 'big')

def modinv(a: int, m: int) -> int:
    """Return the modular inverse of a modulo m."""
    def egcd(x: int, y: int):
        if y == 0:
            return (x, 1, 0)
        g, s, t = egcd(y, x % y)
        return (g, t, s - (x // y) * t)
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError(f"{a} has no modular inverse modulo {m}")
    return x % m

def recv_until(sock: socket.socket, delim: bytes = b'> ') -> bytes:
    data = b''
    while not data.endswith(delim):
        chunk = sock.recv(1)
        if not chunk:
            raise EOFError("Connection closed unexpectedly")
        data += chunk
    return data

def recv_line(sock: socket.socket) -> bytes:
    data = b''
    while not data.endswith(b'\n'):
        chunk = sock.recv(1)
        if not chunk:
            raise EOFError("Connection closed unexpectedly")
        data += chunk
    return data

def send_line(sock: socket.socket, line: str) -> None:
    sock.sendall(line.encode() + b'\n')

def parse_signature_line(line: bytes) -> int:
    """Extract the integer signature from the server’s response."""
    prefix = b"Signature: "
    if not line.startswith(prefix):
        raise ValueError(f"Unexpected signature line: {line!r}")
    return int(line[len(prefix):].strip())

def parse_encryption_line(line: bytes) -> int:
    """Extract the integer ciphertext from the server’s response."""
    prefix = b"enc: "
    if not line.startswith(prefix):
        raise ValueError(f"Unexpected encryption line: {line!r}")
    return int(line[len(prefix):].strip())

def get_signatures(sock: socket.socket, e: int, count: int = 6) -> List[Tuple[int, int]]:
    """Collect (hash, signature) pairs from the signing oracle."""
    pairs: List[Tuple[int, int]] = []
    for _ in range(count):
        recv_until(sock, b'> ')
        send_line(sock, '1')  # Sign a message
        recv_until(sock, b'Message to sign: ')
        msg = ''.join(random.choices(string.ascii_letters + string.digits, k=8)).encode()
        send_line(sock, msg.decode())
        sig_line = recv_line(sock)
        signature = parse_signature_line(sig_line)
        h = bytes_to_long(sha256(msg).digest())
        pairs.append((h, signature))
    return pairs

def get_encryptions(sock: socket.socket, e: int, count: int = 6) -> List[Tuple[int, int]]:
    """Collect (message, ciphertext) pairs from the encryption oracle."""
    pairs: List[Tuple[int, int]] = []
    for _ in range(count):
        recv_until(sock, b'> ')
        send_line(sock, '3')  # Encrypt a message
        recv_until(sock, b'Message to encrypt: ')
        msg_str = ''.join(random.choices(string.digits, k=8))
        m_int = bytes_to_long(msg_str.encode())
        send_line(sock, msg_str)
        enc_line = recv_line(sock)
        cipher = parse_encryption_line(enc_line)
        pairs.append((m_int, cipher))
    return pairs

def compute_prime_from_pairs(e: int, pairs: List[Tuple[int, int]], is_sign: bool) -> int:
    """Recover p or q by taking gcds of differences."""
    diffs: List[int] = []
    for lhs, rhs in pairs:
        if is_sign:
            # signature pairs: rhs = signature, lhs = hash
            diffs.append(pow(rhs, e) - lhs)
        else:
            # encryption pairs: lhs = message, rhs = ciphertext
            diffs.append(pow(lhs, e) - rhs)
    prime = abs(diffs[0])
    for d in diffs[1:]:
        prime = math.gcd(prime, abs(d))
    return prime

def forge_signature_and_get_flag(sock: socket.socket, p: int, q: int, e: int) -> str:
    """Forge a correct RSA signature for b'give_me_flag' and get the flag."""
    n = p * q
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    target_msg = b'give_me_flag'
    h = bytes_to_long(sha256(target_msg).digest())
    forged_sig = pow(h, d, n)
    recv_until(sock, b'> ')
    send_line(sock, '2')                     # Verify a signature
    recv_until(sock, b'Message: ')
    send_line(sock, target_msg.decode())
    recv_until(sock, b'Signature: ')
    send_line(sock, str(forged_sig))
    flag_line = b''
    while True:
        line = recv_line(sock)
        if b'Flag' in line or b'FLAG' in line:
            flag_line = line
            break
        if not line:
            break
    return flag_line.decode().strip()

def main(host: str, port: int) -> None:
    e = 65537
    with socket.create_connection((host, port)) as sock:
        sign_pairs = get_signatures(sock, e, count=6)
        enc_pairs  = get_encryptions(sock, e, count=6)
        p = compute_prime_from_pairs(e, sign_pairs, is_sign=True)
        q = compute_prime_from_pairs(e, enc_pairs,  is_sign=False)
        flag = forge_signature_and_get_flag(sock, p, q, e)
        print(flag)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('host', help='target host (e.g. 34.252.33.37)')
    parser.add_argument('port', type=int, help='target port (e.g. 30914)')
    args = parser.parse_args()
    main(args.host, args.port)
