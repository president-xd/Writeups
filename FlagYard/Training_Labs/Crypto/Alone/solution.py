#!/usr/bin/env python3
"""
ECC Challenge Solver
=====================
Attack chain:
1. Connect to server -> get Q = flag * G
2. Recover redacted a, b from two curve equations (G and Q are on the curve)
3. Check discriminant -> if 0, curve is SINGULAR (not a real elliptic curve)
4. Singular curve -> map ECDLP to trivial DLP in additive or multiplicative group
5. Recover flag
"""

import socket
import re
import math
from Crypto.Util.number import inverse, GCD

# ======================== CURVE PARAMETERS ========================
p = 5543966681219200262244879276566495076752188912561997862121390917883675139
gx = 3641903416831417977189259449090363065201917379578797284702039019013982173
gy = 2005949206451726543928867259831604040421191299918568920753402255996229049


# ======================== MATH UTILITIES ========================

def sqrt_mod(a, p):
    """Square root mod p. Uses simple formula for p = 3 (mod 4), else Tonelli-Shanks."""
    a = a % p
    if a == 0:
        return 0
    if p % 4 == 3:
        r = pow(a, (p + 1) // 4, p)
        return r if pow(r, 2, p) == a else None
    # Tonelli-Shanks
    if pow(a, (p - 1) // 2, p) != 1:
        return None
    q, s = p - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    m, c, t, r = s, pow(z, q, p), pow(a, q, p), pow(a, (q + 1) // 2, p)
    while True:
        if t == 1:
            return r
        i, tmp = 0, t
        while tmp != 1:
            tmp = pow(tmp, 2, p)
            i += 1
        b = pow(c, 1 << (m - i - 1), p)
        m, c, t, r = i, pow(b, 2, p), t * pow(b, 2, p) % p, r * b % p


def is_prime(n, k=25):
    """Miller-Rabin primality test."""
    if n < 2: return False
    if n < 4: return True
    if n % 2 == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    import random
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def pollard_rho(n):
    """Pollard's rho factoring."""
    if n % 2 == 0: return 2
    import random
    while True:
        x = random.randrange(2, n)
        y, c, d = x, random.randrange(1, n), 1
        while d == 1:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = GCD(abs(x - y), n)
        if d != n:
            return d


def factor(n):
    """Fully factor n using trial division + Pollard's rho."""
    if n <= 1:
        return {}
    factors = {}
    # Trial division up to 10^6
    for d in range(2, min(10**6 + 1, int(n**0.5) + 2)):
        while n % d == 0:
            factors[d] = factors.get(d, 0) + 1
            n //= d
        if d * d > n:
            break
    if n <= 1:
        return factors
    # Pollard's rho for remaining
    stack = [n]
    while stack:
        num = stack.pop()
        if num == 1:
            continue
        if is_prime(num):
            factors[num] = factors.get(num, 0) + 1
            continue
        d = pollard_rho(num)
        stack.extend([d, num // d])
    return factors


def bsgs(g, h, order, mod):
    """Baby-step giant-step: find x s.t. g^x = h (mod mod), 0 <= x < order."""
    m = int(math.isqrt(order)) + 1
    # Baby steps
    table = {}
    val = 1
    for j in range(m):
        if val == h:
            return j
        table[val] = j
        val = val * g % mod
    # Giant steps
    g_inv_m = pow(inverse(g, mod), m, mod)
    gamma = h
    for i in range(m):
        if gamma in table:
            return i * m + table[gamma]
        gamma = gamma * g_inv_m % mod
    return None


def pohlig_hellman(g, h, mod, order, order_factors):
    """Pohlig-Hellman: solve g^x = h (mod mod) given factored order."""
    remainders, moduli = [], []

    for prime, exp in sorted(order_factors.items()):
        pe = prime ** exp
        g_sub = pow(g, order // pe, mod)
        h_sub = pow(h, order // pe, mod)

        # Solve in subgroup of order p^e digit by digit
        gamma = pow(g_sub, pe // prime, mod)  # order = prime
        x_sub = 0
        for k in range(exp):
            g_inv_x = pow(inverse(g_sub, mod), x_sub, mod)
            h_k = pow(g_inv_x * h_sub % mod, pe // (prime ** (k + 1)), mod)
            d_k = bsgs(gamma, h_k, prime, mod)
            if d_k is None:
                print(f"    [!] BSGS failed for prime={prime}, k={k}")
                return None
            x_sub += d_k * (prime ** k)
        
        remainders.append(x_sub % pe)
        moduli.append(pe)
        print(f"    x = {x_sub % pe} (mod {pe})")

    return crt(remainders, moduli)


def crt(remainders, moduli):
    """Chinese Remainder Theorem."""
    M = 1
    for m in moduli:
        M *= m
    result = 0
    for r, m in zip(remainders, moduli):
        Mi = M // m
        yi = inverse(Mi % m, m)
        result = (result + r * Mi * yi) % M
    return result


# ======================== SINGULAR CURVE ATTACKS ========================

def solve_cusp(gx, gy, Qx, Qy, xs):
    """
    Cusp case: y² = (x - xs)³  (when a=0, b=0, xs=0 or 3xs=0)
    Group E_ns ≅ (F_p, +)  (additive group)
    Map: phi(x,y) = (x - xs) / y
    phi(nG) = n * phi(G)  ->  n = phi(Q) * phi(G)^-1  (mod p)
    """
    print("[*] CUSP: y^2 = (x - xs)^3 -> additive group, trivial DLP")
    phi_G = ((gx - xs) * inverse(gy, p)) % p
    phi_Q = ((Qx - xs) * inverse(Qy, p)) % p
    n = (phi_Q * inverse(phi_G, p)) % p
    return n


def solve_node_split(gx, gy, Qx, Qy, xs, s):
    """
    Split node: y^2 = (x-xs)^2 * (x + 2xs), with rational slopes +/-s = +/-sqrt(3xs)
    Group E_ns ~ (F_p*, x)  (multiplicative group)
    Map: phi(x,y) = (y + s(x-xs)) / (y - s(x-xs))
    phi(nG) = phi(G)^n  ->  solve DLP in F_p*  via Pohlig-Hellman
    """
    print("[*] SPLIT NODE: y^2 = (x-xs)^2*(x+2xs) -> multiplicative group F_p*")

    def phi(px, py):
        u = (px - xs) % p
        num = (py + s * u) % p
        den = (py - s * u) % p
        return (num * inverse(den, p)) % p

    t_G = phi(gx, gy)
    t_Q = phi(Qx, Qy)
    print(f"    phi(G) = {t_G}")
    print(f"    phi(Q) = {t_Q}")

    # Verify: t_G^n = t_Q (mod p)
    # Solve DLP in F_p* of order p-1
    pm1 = p - 1
    print(f"[*] Factoring p-1 for Pohlig-Hellman...")
    factors = factor(pm1)
    print(f"    p-1 = {' * '.join(f'{k}^{v}' if v > 1 else str(k) for k,v in sorted(factors.items()))}")

    max_prime = max(factors.keys())
    print(f"    Largest prime factor: {max_prime} ({max_prime.bit_length()} bits)")
    if max_prime > 2**48:
        print(f"    [!] WARNING: Largest factor is large, BSGS may be slow")

    print(f"[*] Running Pohlig-Hellman...")
    n = pohlig_hellman(t_G, t_Q, p, pm1, factors)
    return n


def solve_node_nonsplit(gx, gy, Qx, Qy, xs, c):
    """
    Non-split node: slopes +/-sqrt(c) are not in F_p (c is QNR).
    Group E_ns ~ {elements of norm 1 in F_{p^2}*}
    Map via: phi(x,y) = (y + sqrt(c)*(x-xs)) / (y - sqrt(c)*(x-xs))  in F_{p^2}
    """
    print("[*] NON-SPLIT NODE: working in F_{p^2}")

    # Work in F_{p^2} = F_p[i] where i^2 = c (since c is QNR, i = sqrt(c) not in F_p)
    # Elements: (a + b*i) with a,b in F_p
    # If i^2 = c, then (a+bi)(d+ei) = (ad + bec) + (ae + bd)i

    # phi(x,y) = (y + i*(x-xs)) / (y - i*(x-xs))
    # Numerator:   (y, (x-xs))  as (real, imag)
    # Denominator: (y, -(x-xs)) as (real, imag)

    def fp2_mul(a, b, c_val):
        """Multiply (a0+a1*i) * (b0+b1*i) where i^2=c_val, all mod p."""
        return ((a[0]*b[0] + a[1]*b[1]*c_val) % p,
                (a[0]*b[1] + a[1]*b[0]) % p)

    def fp2_inv(a, c_val):
        """Inverse of (a0+a1*i) where i^2=c_val, mod p."""
        # norm = a0^2 - c_val*a1^2
        norm = (a[0]*a[0] - c_val*a[1]*a[1]) % p
        norm_inv = inverse(norm, p)
        return (a[0] * norm_inv % p, (-a[1] * norm_inv) % p)

    def fp2_pow(base, exp, c_val):
        """Compute base^exp in F_{p^2}."""
        result = (1, 0)
        b = base
        while exp > 0:
            if exp & 1:
                result = fp2_mul(result, b, c_val)
            b = fp2_mul(b, b, c_val)
            exp >>= 1
        return result

    def phi(px, py):
        u = (px - xs) % p
        num = (py, u)      # py + i*u
        den = (py, (-u) % p)  # py - i*u
        den_inv = fp2_inv(den, c)
        return fp2_mul(num, den_inv, c)

    t_G = phi(gx, gy)
    t_Q = phi(Qx, Qy)
    print(f"    phi(G) = {t_G[0]} + {t_G[1]}*i")
    print(f"    phi(Q) = {t_Q[0]} + {t_Q[1]}*i")

    # The image has order dividing p+1 (norm-1 elements of F_{p^2}*)
    # Solve DLP: t_Q = t_G^n in this subgroup
    order = p + 1
    print(f"[*] Factoring p+1 for Pohlig-Hellman in F_{{p^2}}*...")
    factors = factor(order)
    print(f"    p+1 = {' * '.join(f'{k}^{v}' if v > 1 else str(k) for k,v in sorted(factors.items()))}")

    max_prime = max(factors.keys())
    print(f"    Largest prime factor: {max_prime} ({max_prime.bit_length()} bits)")

    # Pohlig-Hellman in F_{p^2}
    remainders, moduli = [], []
    for prime, exp in sorted(factors.items()):
        pe = prime ** exp
        g_sub = fp2_pow(t_G, order // pe, c)
        h_sub = fp2_pow(t_Q, order // pe, c)

        gamma = fp2_pow(g_sub, pe // prime, c)  # order = prime
        x_sub = 0
        for k in range(exp):
            g_inv_x = fp2_pow(fp2_inv(g_sub, c), x_sub, c)
            h_k_base = fp2_mul(g_inv_x, h_sub, c)
            h_k = fp2_pow(h_k_base, pe // (prime ** (k + 1)), c)

            # BSGS in F_{p^2} subgroup of order prime
            m = int(math.isqrt(prime)) + 1
            table = {}
            val = (1, 0)
            for j in range(m):
                table[val] = j
                val = fp2_mul(val, gamma, c)

            gamma_inv_m = fp2_pow(fp2_inv(gamma, c), m, c)
            cur = h_k
            d_k = None
            for i_step in range(m):
                if cur in table:
                    d_k = i_step * m + table[cur]
                    break
                cur = fp2_mul(cur, gamma_inv_m, c)

            if d_k is None:
                print(f"    [!] BSGS failed for prime={prime}, k={k}")
                return None
            x_sub += d_k * (prime ** k)

        remainders.append(x_sub % pe)
        moduli.append(pe)
        print(f"    x ≡ {x_sub % pe} (mod {pe})")

    n = crt(remainders, moduli)
    return n


# ======================== MAIN SOLVER ========================

def solve():
    # ---- Step 0: Connect and get Q ----
    print("=" * 60)
    print(" ECC Singular Curve Exploit")
    print("=" * 60)
    print(f"\n[*] Connecting to tcp.flagyard.com:25103 ...")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(15)
    sock.connect(('tcp.flagyard.com', 28473))

    data = b''
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    sock.close()

    response = data.decode().strip()
    print(f"[*] Server response:\n    {response}\n")

    # Parse Q from output
    match = re.search(r'Point\(x=(\d+),\s*y=(\d+)\)', response)
    if not match:
        match = re.search(r'\((\d+),\s*(\d+)\)', response)
    if not match:
        print(f"[!] Could not parse Q from: {response}")
        return
    Qx, Qy = int(match.group(1)), int(match.group(2))
    print(f"[+] Q = Point(x={Qx}, y={Qy})")

    # ---- Step 1: Recover a, b ----
    # gy^2 = gx^3 + a*gx + b (mod p)  ... (1)
    # Qy^2 = Qx^3 + a*Qx + b (mod p)  ... (2)
    # (2)-(1): a = [(Qy^2-Qx^3) - (gy^2-gx^3)] / (Qx-gx) mod p
    print("\n[*] Recovering curve parameters a, b ...")
    rhs_G = (pow(gy, 2, p) - pow(gx, 3, p)) % p
    rhs_Q = (pow(Qy, 2, p) - pow(Qx, 3, p)) % p

    a = (rhs_Q - rhs_G) * inverse((Qx - gx) % p, p) % p
    b = (rhs_G - a * gx) % p

    # Verify both points
    assert (pow(gy, 2, p) - pow(gx, 3, p) - a * gx - b) % p == 0, "G verification failed!"
    assert (pow(Qy, 2, p) - pow(Qx, 3, p) - a * Qx - b) % p == 0, "Q verification failed!"
    print(f"[+] a = {a}")
    print(f"[+] b = {b}")
    print(f"[+] Both G and Q verified on curve [OK]")

    # ---- Step 2: Check discriminant ----
    disc = (4 * pow(a, 3, p) + 27 * pow(b, 2, p)) % p
    print(f"\n[*] Discriminant D = 4a^3 + 27b^2 mod p = {disc}")

    if disc != 0:
        print("[*] Non-singular curve -- would need Smart's attack or Pohlig-Hellman on curve order")
        print("[!] This case requires SageMath. Exiting.")
        return

    # ---- Step 3: Singular curve exploit ----
    print("\n" + "=" * 60)
    print(" SINGULAR CURVE DETECTED -- ECDLP collapses!")
    print("=" * 60)

    # Find singular point xs: 3*xs^2 + a = 0 (mod p)  and  xs^3 + a*xs + b = 0 (mod p)
    xs_sq = (-a * inverse(3, p)) % p
    xs = sqrt_mod(xs_sq, p)

    if xs is None:
        print("[!] sqrt failed -- trying negation")
        xs = (-sqrt_mod((-xs_sq) % p, p)) % p if sqrt_mod((-xs_sq) % p, p) is not None else None

    if xs is not None:
        if (pow(xs, 3, p) + a * xs + b) % p != 0:
            xs = (-xs) % p
        if (pow(xs, 3, p) + a * xs + b) % p != 0:
            print("[!] Singular point verification failed")
            return
    else:
        print("[!] Could not find singular point")
        return

    print(f"[+] Singular point xs = {xs}")

    # Determine cusp vs node: y^2 = (x-xs)^3 + 3xs*(x-xs)^2
    # After substitution u = x - xs:  y^2 = u^3 + c*u^2  where c = 3*xs
    c_coeff = (3 * xs) % p
    print(f"[*] Translated curve: y^2 = u^3 + {c_coeff}*u^2")

    if c_coeff == 0:
        # ---- CUSP: additive group, trivial ----
        n = solve_cusp(gx, gy, Qx, Qy, xs)
    else:
        # ---- NODE ----
        s = sqrt_mod(c_coeff, p)
        if s is not None:
            # Split node: slopes +/-s are rational
            n = solve_node_split(gx, gy, Qx, Qy, xs, s)
        else:
            # Non-split node: slopes irrational, work in F_{p^2}
            n = solve_node_nonsplit(gx, gy, Qx, Qy, xs, c_coeff)

    if n is None:
        print("\n[!] Failed to recover flag scalar")
        return

    # ---- Step 4: Decode flag ----
    # n = flag mod (p-1). If flag > p-1, need to find flag = n + k*(p-1).
    # Use known prefix 'FlagY{' to constrain k via CRT.
    print(f"\n[*] Recovered scalar n = {n}")
    pm1 = p - 1
    print(f"[*] n has {n.bit_length()} bits, p-1 has {pm1.bit_length()} bits")

    # First try: flag = n directly
    nbytes = (n.bit_length() + 7) // 8
    direct = n.to_bytes(nbytes, 'little')
    if direct[:6] == b'FlagY{' and all(32 <= b < 127 for b in direct):
        print(f"\n[+] FLAG: {direct.decode('ascii')}")
        return

    # Flag wraps: use CRT with 'FlagY{' prefix
    print("[*] Flag > p-1, using CRT with 'FlagY{{' prefix to find k...")
    pm1 = p - 1
    target_prefix = int.from_bytes(b'FlagY{', 'little')
    mod_prefix = 2**48  # 6 bytes

    diff = (target_prefix - n % mod_prefix) % mod_prefix
    g = GCD(pm1 % mod_prefix, mod_prefix)

    if diff % g != 0:
        print("[!] CRT incompatible with 'FlagY{{' prefix")
        return

    reduced_mod = mod_prefix // g
    reduced_pm1 = (pm1 // g) % reduced_mod
    reduced_diff = (diff // g) % reduced_mod
    k0 = reduced_diff * inverse(reduced_pm1, reduced_mod) % reduced_mod

    print(f"[*] k = {k0} (mod {reduced_mod}), searching...")

    for i in range(50_000_000):
        k = k0 + i * reduced_mod
        flag_int = n + k * pm1
        if flag_int.bit_length() > 800:
            break
        nbytes = (flag_int.bit_length() + 7) // 8
        if nbytes > 100:
            break
        flag_bytes = flag_int.to_bytes(nbytes, 'little')
        if flag_bytes[:6] != b'FlagY{':
            continue
        stripped = flag_bytes.rstrip(b'\x00')
        if stripped[-1] == ord('}') and all(32 <= b < 127 for b in stripped):
            print(f"\n[+] Found at k={k} (iteration {i})")
            print(f"\n{'='*60}")
            print(f" FLAG: {stripped.decode('ascii')}")
            print(f"{'='*60}")
            return

    print("[!] Flag not found in search range")


if __name__ == '__main__':
    solve()
