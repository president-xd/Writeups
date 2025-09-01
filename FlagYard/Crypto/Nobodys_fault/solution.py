#!/usr/bin/env python3
# exploit for broken RSA service (challenge.py)

from pwn import remote
from Crypto.Util.number import bytes_to_long, inverse
from hashlib import sha256
from math import gcd as math_gcd

E = 65537

# try to load gmpy2 for faster gcd/pow
try:
    import gmpy2
    mpz = gmpy2.mpz
    gcd_func = gmpy2.gcd
    is_prime = gmpy2.is_prime
    powmod = gmpy2.powmod
    have_gmpy2 = True
except Exception:
    mpz = int
    gcd_func = math_gcd
    from Crypto.Util.number import isPrime as is_prime
    def powmod(a, b, m): return pow(a, b, m)
    have_gmpy2 = False

def sendline(conn, s: bytes):
    conn.send(s + b"\n")

def get_encryption(conn, msg_bytes: bytes) -> int:
    conn.recvuntil(b"> ")
    sendline(conn, b"3")
    conn.recvuntil(b"Message to encrypt: ")
    conn.send(msg_bytes + b"\n")
    line = conn.recvline().strip()
    return int(line.split()[1])

def get_signature(conn, msg_bytes: bytes) -> int:
    conn.recvuntil(b"> ")
    sendline(conn, b"1")
    conn.recvuntil(b"Message to sign: ")
    conn.send(msg_bytes + b"\n")
    line = conn.recvline().strip()
    return int(line.split()[1])

def recover_q(conn):
    msgs = [b'\x02', b'\x03', b'\x04', b'\x05']
    g = mpz(0)
    for m in msgs:
        m_int = bytes_to_long(m)
        enc = mpz(get_encryption(conn, m))
        if g == 0:
            # first one: base is small, so pow() is fine
            diff = mpz(pow(m_int, E)) - enc
            g = abs(diff)
        else:
            diff = (powmod(mpz(m_int), E, g) - enc) % g
            g = abs(gcd_func(g, diff))
        if g > 1 and is_prime(g) and g.bit_length() == 512:
            return int(g)
    raise RuntimeError("q recovery failed")

def recover_p(conn, q):
    msgs = [b'a', b'b', b'c', b'd', b'e']
    g = mpz(0)
    for m in msgs:
        sig = mpz(get_signature(conn, m))
        h = mpz(bytes_to_long(sha256(m).digest()))
        if g == 0:
            diff = abs((sig ** E) - h) if have_gmpy2 else abs(pow(int(sig), E) - int(h))
            g = diff
        else:
            diff = (powmod(sig, E, g) - h) % g
            g = abs(gcd_func(g, diff))
        if g > 1 and is_prime(g) and g.bit_length() == 512 and g != q:
            return int(g)
    raise RuntimeError("p recovery failed")

def submit_signature(conn, p, q):
    n = p * q
    msg = b'give_me_flag'
    H = bytes_to_long(sha256(msg).digest())
    d_p = inverse(E, p - 1)
    d_q = inverse(E, q - 1)
    sig_p = pow(H, d_p, p)
    sig_q = pow(H, d_q, q)
    inv_p_mod_q = inverse(p % q, q)
    t = ((sig_q - sig_p) * inv_p_mod_q) % q
    sig = (sig_p + p * t) % n
    # verify with server
    conn.recvuntil(b"> ")
    sendline(conn, b"2")
    conn.recvuntil(b"Message: ")
    conn.send(msg + b"\n")
    conn.recvuntil(b"Signature: ")
    conn.send(str(sig).encode() + b"\n")
    out = conn.recvall(timeout=2)
    print(out.decode(errors="ignore"))

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="34.252.33.37")
    ap.add_argument("--port", type=int, default=31142)
    args = ap.parse_args()
    conn = remote(args.host, args.port)
    print("[*] Recovering q ...")
    q = recover_q(conn)
    print(f"[+] q recovered ({q.bit_length()} bits)")
    print("[*] Recovering p ...")
    p = recover_p(conn, q)
    print(f"[+] p recovered ({p.bit_length()} bits)")
    print("[*] Getting flag ...")
    submit_signature(conn, p, q)
    conn.close()

if __name__ == "__main__":
    main()