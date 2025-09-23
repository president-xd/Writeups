#!/usr/bin/env python3
# exploit.py
# Usage:
#   python3 exploit.py --remote <host> <port>
#   python3 exploit.py --local <path/to/challenge_executable_or_sage_script>
#
# The script performs:
#  1) Requests two signatures on chosen messages
#  2) Computes k and d
#  3) Computes signature for 'IdkJusTcalculateHash'
#  4) Sends signature to "Get flag" and prints server response (flag)

import argparse
import hashlib
import socket
import subprocess
import sys
import time
from typing import Tuple

# Curve parameters copied from the challenge
p = 0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
a = 0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc
b = 0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00
Gx = 0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66
Gy = 0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650
n = 0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409

# modular inverse wrapper
def inv(x, m):
    return pow(x, -1, m)

# simple elliptic curve operations for curve over prime p
# Points are tuples (x,y). Use None for point at infinity.
def is_on_curve(P):
    if P is None:
        return True
    x,y = P
    return (y*y - (x*x*x + a*x + b)) % p == 0

def point_add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    x1,y1 = P
    x2,y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        lam = (3 * x1 * x1 + a) * inv(2 * y1 % p, p) % p
    else:
        lam = (y2 - y1) * inv((x2 - x1) % p, p) % p
    x3 = (lam*lam - x1 - x2) % p
    y3 = (lam*(x1 - x3) - y1) % p
    return (x3, y3)

def scalar_mult(k, P):
    if k % n == 0 or P is None:
        return None
    if k < 0:
        # negative scalar
        return scalar_mult(-k, (P[0], (-P[1]) % p))
    R = None
    Q = P
    while k:
        if k & 1:
            R = point_add(R, Q)
        Q = point_add(Q, Q)
        k >>= 1
    return R

# helper to compute sha512 int
def sha512_int(msg: str) -> int:
    return int(hashlib.sha512(msg.encode()).hexdigest(), 16)

# --------- Communication helpers ---------
# Protocol helpers for local (subprocess) mode and remote (socket) mode.

class LocalProc:
    def __init__(self, path):
        # spawn the program; user may need to run with 'sage' if script requires sage interpreter,
        # so allow path to be: "sage challenge.sage" or direct binary.
        if isinstance(path, list):
            self.p = subprocess.Popen(path, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=0)
        else:
            # try to guess: if path is a script ending with .sage or .py, run with 'sage' or 'python3'
            if path.endswith('.sage'):
                cmd = ['sage', path]
            else:
                cmd = [path]
            self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=0)
    def recv_until(self, token, timeout=2.0):
        out = ""
        start = time.time()
        while True:
            # read one byte at a time to avoid blocking on large reads
            ch = self.p.stdout.read(1)
            if ch == '':
                # process ended
                break
            out += ch
            if token in out:
                return out
            if time.time() - start > timeout:
                return out
        return out
    def send(self, data: str):
        self.p.stdin.write(data)
        self.p.stdin.flush()
    def close(self):
        try:
            self.p.kill()
        except:
            pass

class RemoteSock:
    def __init__(self, host, port, timeout=6.0):
        self.sock = socket.create_connection((host, int(port)), timeout=timeout)
        self.sock.settimeout(6.0)
        self.buf = b''

    def recv_until(self, token, timeout=6.0):
        """
        token: either bytes or str. Returns a decoded str (utf-8, errors='ignore').
        """
        if isinstance(token, str):
            token_b = token.encode()
        else:
            token_b = token

        end = time.time() + timeout
        while time.time() < end:
            try:
                data = self.sock.recv(4096)
            except socket.timeout:
                data = b''
            if not data:
                break
            self.buf += data
            if token_b in self.buf:
                idx = self.buf.index(token_b) + len(token_b)
                out = self.buf[:idx]
                self.buf = self.buf[idx:]
                return out.decode(errors='ignore')
        # timeout or socket closed: return whatever we have (decoded)
        tmp = self.buf
        self.buf = b''
        return tmp.decode(errors='ignore')

    def send(self, data: str):
        self.sock.sendall(data.encode())

    def close(self):
        try:
            self.sock.close()
        except:
            pass


# parse signature text "Signature: <r> <s>"
def parse_signature(s: str) -> Tuple[int,int]:
    # find "Signature:" and then two ints
    if "Signature:" not in s:
        # sometimes output might be different; try to extract numbers
        parts = s.strip().split()
    else:
        parts = s.split("Signature:")[-1].strip().split()
    if len(parts) < 2:
        raise ValueError("Couldn't parse signature from: " + s)
    r = int(parts[0].strip())
    s = int(parts[1].strip())
    return r, s

# high-level interaction: get signature for a message
def request_signature(sess, msg: str) -> Tuple[int,int]:
    # sess supports recv_until(token) and send(string)
    # menu shows "1. Sign" "2. Get flag"
    sess.recv_until("Enter your choice: ")
    sess.send("1\n")
    sess.recv_until("Enter the message: ")
    sess.send(msg + "\n")
    out = sess.recv_until("\n")  # read next line
    # in some setups output may contain more; read a bit more
    out_extra = sess.recv_until("\n", timeout=0.5)
    out += out_extra
    try:
        r,s = parse_signature(out)
    except Exception as e:
        # try to collect more output
        out_more = sess.recv_until("Enter your choice: ", timeout=1.0)
        out += out_more
        r,s = parse_signature(out)
    return r,s

# request flag using r,s (returns response)
def request_flag(sess, r, s):
    sess.recv_until("Enter your choice: ")
    sess.send("2\n")
    sess.recv_until("Enter r: ")
    sess.send(str(r) + "\n")
    sess.recv_until("Enter s: ")
    sess.send(str(s) + "\n")
    # read response (may include flag)
    resp = sess.recv_until("\n", timeout=2.0)
    # read more if available
    more = sess.recv_until("\n", timeout=0.5)
    resp += more
    return resp

# core exploit procedure given an open session object
def exploit_session(sess):
    # choose two different messages (must not contain the banned substring)
    m1_text = "A message for signature #1"
    m2_text = "Another different message #2"

    # request two signatures
    r1, s1 = request_signature(sess, m1_text)
    print("[*] sig1 r,s:", r1, s1)
    r2, s2 = request_signature(sess, m2_text)
    print("[*] sig2 r,s:", r2, s2)

    if r1 != r2:
        print("[!] Warning: r values differ. Nonce reuse expected same r. But reuse can happen with same k => same r. If r differ exploit may fail.")
    # compute message hashes
    m1 = sha512_int(m1_text)
    m2 = sha512_int(m2_text)

    # compute k
    delta_s = (s1 - s2) % n
    if delta_s == 0:
        raise Exception("s1 - s2 == 0, can't invert")
    k = ((m1 - m2) * inv(delta_s, n)) % n
    print("[*] recovered k:", k)

    # recover d: d = (s1*k - m1) * inv(r, n) mod n
    if r1 % n == 0:
        raise Exception("r == 0")
    d = ((s1 * k - m1) * inv(r1, n)) % n
    print("[*] recovered d:", d)

    # compute signature for protected message
    protected = "IdkJusTcalculateHash"
    m_prot = sha512_int(protected)
    # compute Q = k*G to get r
    G = (Gx, Gy)
    Q = scalar_mult(k, G)
    if Q is None:
        raise Exception("k*G is infinity")
    r_prot = Q[0] % n
    s_prot = (inv(k, n) * (m_prot + r_prot * d)) % n
    print("[*] computed protected r,s:", r_prot, s_prot)

    # send to get flag
    resp = request_flag(sess, r_prot, s_prot)
    return resp

# ---------- Main CLI ----------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--remote", nargs=2, metavar=('host','port'), help="remote host and port")
    parser.add_argument("--local", nargs=1, metavar=('path'), help="local path to challenge executable or sage script")
    args = parser.parse_args()

    if args.remote:
        host, port = args.remote
        print("[*] connecting remote", host, port)
        sess = RemoteSock(host, int(port))
        try:
            out = sess.recv_until("Enter your choice: ", timeout=2.0)
            print(out)
        except Exception:
            out = ""
        print(out)
        try:
            result = exploit_session(sess)
            print("[+] Server response:")
            print(result)
        finally:
            sess.close()
    elif args.local:
        path = args.local[0]
        # allow passing the path as list if user wants ['sage', 'challenge.sage']
        print("[*] launching local process:", path)
        if path.startswith("sage "):
            cmd = path.split()
            sess = LocalProc(cmd)
        else:
            sess = LocalProc(path)
        try:
            # wait for menu
            sess.recv_until("Enter your choice: ")
            result = exploit_session(sess)
            print("[+] Local program response:")
            print(result)
        finally:
            sess.close()
    else:
        print("Provide --remote host port or --local path")
        sys.exit(1)

if __name__ == "__main__":
    main()
