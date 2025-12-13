#!/usr/bin/env python3
import socket, re, math
from Crypto.Util.number import long_to_bytes

HOST = "tcp.flagyard.com"
PORT = 23248

L_BITS = 8

# ---------------- I/O ----------------
def recv_until(sock, token: bytes, limit=1_000_000):
    data = b""
    while token not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > limit:
            raise RuntimeError("sync lost (too much data)")
    return data

def sendline(sock, s: str):
    sock.sendall((s + "\n").encode())

def parse_ct(banner: str):
    m = re.search(r"ct=\((\d+),\s*(\d+),\s*(\d+),\s*(\d+)\)", banner)
    if not m:
        raise RuntimeError("could not parse ct")
    return tuple(int(m.group(i)) for i in range(1, 5))

def parse_tuple4(text: str):
    m = re.search(r"\((\d+),\s*(\d+),\s*(\d+),\s*(\d+)\)", text)
    if not m:
        return None
    return tuple(int(m.group(i)) for i in range(1, 5))

def parse_point(text: str):
    m = re.search(r"m=\s*(\d+)\s+(\d+)", text)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)))

def oracle_enc(sock, m_int: int):
    sendline(sock, "1")
    recv_until(sock, b"plaintext>>")
    sendline(sock, str(m_int))
    out = recv_until(sock, b">>").decode(errors="ignore")
    ct = parse_tuple4(out)
    if ct is None:
        raise RuntimeError("failed to parse enc output")
    return ct, out

def oracle_dec(sock, ct4):
    sendline(sock, "2")
    recv_until(sock, b"ciphertext>>")
    sendline(sock, ",".join(map(str, ct4)))
    out = recv_until(sock, b">>").decode(errors="ignore")
    P = parse_point(out)
    if P is None:
        # server may say "bad ciphertext" or "not that easy"
        return None, out
    return P, out

# ---------------- math helpers (mod p unknown at first) ----------------
def det_zero_mod_p(points):
    # points: list of (x,y) over Z but satisfying y^2 = x^3 + ax + b (mod p)
    # Let t_i = y_i^2 - x_i^3
    # then t_i - t_j = a(x_i - x_j) (mod p)
    # eliminate a:
    # (t_i - t_j)(x_k - x_l) - (t_k - t_l)(x_i - x_j) == 0 (mod p)
    ts = [y*y - x*x*x for (x,y) in points]
    xs = [x for (x,y) in points]
    vals = []
    n = len(points)
    # take a bunch of combinations (not all)
    for i in range(n):
        for j in range(i+1, n):
            for k in range(n):
                for l in range(k+1, n):
                    if len(vals) > 80:
                        return vals
                    v = (ts[i]-ts[j])*(xs[k]-xs[l]) - (ts[k]-ts[l])*(xs[i]-xs[j])
                    if v != 0:
                        vals.append(abs(v))
    return vals

def recover_p(points):
    vals = det_zero_mod_p(points)
    if not vals:
        raise RuntimeError("not enough algebraic relations to recover p")
    g = 0
    for v in vals:
        g = math.gcd(g, v)
    # g can be a multiple of p (or p times small cofactors). Remove small factors.
    # (we only need the prime modulus; typical: g == p or 2p etc.)
    for small in [2,3,5,7,11,13,17,19,23,29,31,37,41]:
        while g % small == 0:
            g //= small
    return g

def modinv(a, p):
    return pow(a % p, p-2, p)

def recover_a_b(points, p):
    # Use two points to solve for a, then compute b.
    # t_i = y^2 - x^3 (mod p), so t_i = a x_i + b (mod p)
    for i in range(len(points)):
        for j in range(i+1, len(points)):
            xi, yi = points[i]
            xj, yj = points[j]
            if (xi - xj) % p == 0:
                continue
            ti = (yi*yi - xi*xi*xi) % p
            tj = (yj*yj - xj*xj*xj) % p
            a = ((ti - tj) * modinv(xi - xj, p)) % p
            b = (ti - a*xi) % p
            return a, b
    raise RuntimeError("could not recover a,b (degenerate points)")

# ---------------- EC over recovered (p,a,b) ----------------
def is_on_curve(P, p, a, b):
    if P is None:
        return True
    x,y = P
    return (y*y - (x*x*x + a*x + b)) % p == 0

def ec_neg(P, p):
    if P is None:
        return None
    x,y = P
    return (x, (-y) % p)

def ec_add(P, Q, p, a):
    if P is None: return Q
    if Q is None: return P
    x1,y1 = P
    x2,y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P != Q:
        lam = ((y2 - y1) * modinv(x2 - x1, p)) % p
    else:
        lam = ((3*x1*x1 + a) * modinv(2*y1, p)) % p
    x3 = (lam*lam - x1 - x2) % p
    y3 = (lam*(x1 - x3) - y1) % p
    return (x3,y3)

def ec_sub(P, Q, p, a):
    return ec_add(P, ec_neg(Q, p), p, a)

# ---------------- Solve ----------------
def main():
    sock = socket.create_connection((HOST, PORT))

    banner = recv_until(sock, b">>").decode(errors="ignore")
    print(banner)

    ct = parse_ct(banner)
    C1 = (ct[0], ct[1])
    C2 = (ct[2], ct[3])

    # 1) collect several plaintext points via enc(i) then dec(enc(i))
    pts = []
    enc_cts = []
    i = 0
    # gather 8 points (enough redundancy)
    while len(pts) < 8:
        ct_i, _ = oracle_enc(sock, i)
        # avoid server's "not that easy" filter for later: it forbids dec if C2x or C2y equals target's C2x/C2y
        if ct_i[2] == C2[0] or ct_i[3] == C2[1]:
            i += 1
            continue
        P, out = oracle_dec(sock, ct_i)
        if P is None:
            i += 1
            continue
        pts.append(P)
        enc_cts.append(ct_i)
        i += 1

    # 2) recover p, then a,b
    p = recover_p(pts)
    a, b = recover_a_b(pts, p)

    # sanity checks
    assert is_on_curve(pts[0], p, a, b), "recovered curve params failed check"
    assert is_on_curve(C1, p, a, b), "C1 not on recovered curve"
    assert is_on_curve(C2, p, a, b), "C2 not on recovered curve"

    print(f"[+] Recovered p  = {p}")
    print(f"[+] Recovered a  = {a}")
    print(f"[+] Recovered b  = {b}")

    # 3) get T = encode(0) point (we likely already have it if i=0 succeeded; but let's do it cleanly)
    ct0, _ = oracle_enc(sock, 0)
    if ct0[2] == C2[0] or ct0[3] == C2[1]:
        # extremely unlikely, pick another small m
        ct0, _ = oracle_enc(sock, 1)
    T, out = oracle_dec(sock, ct0)
    if T is None:
        raise RuntimeError("could not obtain T via dec(enc(0/1))")
    assert is_on_curve(T, p, a, b)

    # 4) craft modified ciphertext: C2' = C2 + T (local EC add)
    C2p = ec_add(C2, T, p, a)
    if C2p is None:
        raise RuntimeError("C2 + T = infinity (rerun)")
    if C2p[0] == C2[0] or C2p[1] == C2[1]:
        raise RuntimeError("unlucky: C2' shares x/y with original C2; rerun")

    # 5) oracle decrypt (C1, C2') -> M + T
    forged = (C1[0], C1[1], C2p[0], C2p[1])
    Mp, out = oracle_dec(sock, forged)
    if Mp is None:
        raise RuntimeError("forged dec failed; rerun")
    assert is_on_curve(Mp, p, a, b)

    # 6) recover M = (M+T) - T
    M = ec_sub(Mp, T, p, a)

    # 7) decode flag int from x-coordinate >> 8
    flag_int = M[0] >> L_BITS
    flag_bytes = long_to_bytes(flag_int)

    print("\n[+] flag_int:", flag_int)
    print("[+] flag_bytes:", flag_bytes)
    try:
        print("[+] flag:", flag_bytes.decode())
    except Exception:
        print("[!] flag bytes not utf-8; raw bytes shown above")

    sock.close()

if __name__ == "__main__":
    main()
