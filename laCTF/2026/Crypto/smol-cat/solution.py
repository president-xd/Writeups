import socket, re, base64, struct, time, random, requests
import gmpy2
from gmpy2 import mpz

# ──────────────────────── PoW ────────────────────────

def solve_pow(challenge):
    parts = challenge.split('.')
    d_bytes = base64.b64decode(parts[1])
    d_bytes = b'\x00' * (4 - len(d_bytes)) + d_bytes
    difficulty = struct.unpack('>I', d_bytes)[0]
    x = mpz(int.from_bytes(base64.b64decode(parts[2]), 'big'))
    one, mod, exp = mpz(1), (mpz(1) << 1279) - 1, mpz(1) << 1277
    print(f"PoW: {difficulty} iterations...")
    for i in range(difficulty):
        x = gmpy2.powmod(x, exp, mod) ^ one
        if (i + 1) % 5000 == 0: print(f"  {i+1}/{difficulty}")
    x_int = int(x)
    bl = (x_int.bit_length() + 7) // 8
    return f"s.{base64.b64encode(x_int.to_bytes(bl, 'big') if bl else b'\\x00').decode()}"

# ──────────────────── Factoring ──────────────────────

def factor_n(n):
    """Factor n using: trial div → perfect power → p-1 → factordb → ECM."""
    n = int(n)
    factors = {}

    def record(p, n):
        p = int(p)
        while n % p == 0:
            factors[p] = factors.get(p, 0) + 1
            n //= p
        return n

    # (1) Trial division up to 10^6
    print("  [1] Trial division to 10^6...")
    temp = n
    p = mpz(2)
    while p <= 10**6 and temp > 1:
        if temp % int(p) == 0:
            while temp % int(p) == 0:
                factors[int(p)] = factors.get(int(p), 0) + 1
                temp //= int(p)
            print(f"      factor {int(p)}")
        p = gmpy2.next_prime(p)
    n = temp
    if n <= 1: return factors
    if gmpy2.is_prime(mpz(n)):
        factors[n] = factors.get(n, 0) + 1; return factors

    # (2) Perfect-power check
    print("  [2] Perfect power check...")
    for k in range(2, 100):
        r, exact = gmpy2.iroot(mpz(n), k)
        if exact:
            print(f"      n = {int(r)}^{k}")
            sub = factor_n(int(r))
            for p2, e2 in sub.items():
                factors[p2] = factors.get(p2, 0) + e2 * k
            return factors

    # (3) factordb — submit, poll, get factors (FAST for 200-bit)
    print("  [3] factordb...")
    fdb = factordb_factor(n, timeout=45)
    if fdb:
        for p2, e2 in fdb.items():
            factors[p2] = factors.get(p2, 0) + e2
        return factors

    # (4) Pollard p-1 with increasing bounds
    print("  [4] Pollard p-1...")
    for B1, B2 in [(100_000, 2_000_000), (1_000_000, 20_000_000)]:
        f = pollard_pm1(n, B1, B2)
        if f and 1 < f < n:
            print(f"      p-1 found {f}")
            n = record(f, n)
            if n > 1 and not gmpy2.is_prime(mpz(n)):
                sub = factor_n(n)
                for p2, e2 in sub.items(): factors[p2] = factors.get(p2, 0) + e2
            elif n > 1:
                factors[n] = factors.get(n, 0) + 1
            return factors

    # (5) ECM — Montgomery curves with gmpy2
    print("  [5] ECM...")
    remaining = n
    while remaining > 1 and not gmpy2.is_prime(mpz(remaining)):
        f = ecm_factor(remaining, B1=250_000, curves=500)
        if f and 1 < f < remaining:
            print(f"      ECM found {f}")
            remaining = record(f, remaining)
        else:
            break
    if remaining > 1:
        factors[remaining] = factors.get(remaining, 0) + 1
    return factors


def pollard_pm1(n, B1=100_000, B2=2_000_000):
    a = mpz(2)
    n = mpz(n)
    p = mpz(2)
    while p <= B1:
        pp = int(p)
        while pp * int(p) <= B1: pp *= int(p)
        a = gmpy2.powmod(a, pp, n)
        p = gmpy2.next_prime(p)
    g = gmpy2.gcd(a - 1, n)
    if 1 < g < n: return int(g)
    # Stage 2
    p = gmpy2.next_prime(mpz(B1))
    while p <= B2:
        a = gmpy2.powmod(a, p, n)
        g = gmpy2.gcd(a - 1, n)
        if 1 < g < n: return int(g)
        p = gmpy2.next_prime(p)
    return None


def factordb_factor(n, timeout=40):
    """Submit to factordb and poll until factored."""
    try:
        # Trigger factoring via the web page
        requests.get(f"http://factordb.com/index.php?query={n}", timeout=5)
    except: pass

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = requests.get(f"http://factordb.com/api?query={n}", timeout=5)
            data = resp.json()
            status = data.get('status', '')
            print(f"      factordb status={status}")
            if status in ('FF', 'CF'):
                result = {}
                for f_str, f_exp in data['factors']:
                    fv = int(f_str)
                    if fv > 1:
                        result[fv] = int(f_exp)
                # Verify
                product = 1
                for p, e in result.items(): product *= p ** e
                if product == n:
                    print(f"      factordb done: {result}")
                    return result
                else:
                    print(f"      factordb partial, continuing...")
            time.sleep(3)
        except Exception as ex:
            print(f"      factordb error: {ex}")
            time.sleep(3)
    return None


# ──────────── ECM with Montgomery curves ─────────────

def xDBL(Xp, Zp, a24, n):
    s = (Xp + Zp) % n
    d = (Xp - Zp) % n
    s2 = (s * s) % n
    d2 = (d * d) % n
    diff = (s2 - d2) % n
    X2 = (s2 * d2) % n
    Z2 = (diff * (d2 + a24 * diff)) % n
    return X2, Z2

def xADD(Xp, Zp, Xq, Zq, Xd, Zd, n):
    u = ((Xp - Zp) * (Xq + Zq)) % n
    v = ((Xp + Zp) * (Xq - Zq)) % n
    add = (u + v) % n
    sub = (u - v) % n
    X = (Zd * add * add) % n
    Z = (Xd * sub * sub) % n
    return X, Z

def mont_ladder(Qx, Qz, k, a24, n):
    """Compute [k](Qx:Qz) using Montgomery ladder."""
    R0x, R0z = Qx, Qz
    R1x, R1z = xDBL(Qx, Qz, a24, n)
    bits = bin(k)[3:]  # skip '0b1'
    for bit in bits:
        if bit == '0':
            R1x, R1z = xADD(R0x, R0z, R1x, R1z, Qx, Qz, n)
            R0x, R0z = xDBL(R0x, R0z, a24, n)
        else:
            R0x, R0z = xADD(R0x, R0z, R1x, R1z, Qx, Qz, n)
            R1x, R1z = xDBL(R1x, R1z, a24, n)
    return R0x, R0z

def ecm_factor(n, B1=250_000, curves=500):
    """Lenstra ECM using Montgomery curves."""
    n = mpz(n)
    for curve in range(curves):
        sigma = mpz(random.randint(6, 1 << 30))
        u = (sigma * sigma - 5) % n
        v = (4 * sigma) % n
        diff = (v - u) % n
        sum3 = (3 * u + v) % n

        num = (gmpy2.powmod(diff, 3, n) * sum3) % n
        den = (16 * gmpy2.powmod(u, 3, n) % n * v) % n

        g = gmpy2.gcd(den, n)
        if g == n: continue
        if 1 < g < n: return int(g)

        a24 = (num * gmpy2.invert(den, n)) % n
        Qx = gmpy2.powmod(u, 3, n)
        Qz = gmpy2.powmod(v, 3, n)

        # Stage 1: [M]Q where M = prod(p^k for p prime, p^k <= B1)
        p = mpz(2)
        z_accum = mpz(1)
        count = 0
        while p <= B1:
            pp = int(p)
            while pp * int(p) <= B1: pp *= int(p)
            Qx, Qz = mont_ladder(Qx, Qz, pp, a24, n)
            z_accum = (z_accum * Qz) % n
            count += 1
            if count % 200 == 0:
                g = gmpy2.gcd(z_accum, n)
                if g == n: break
                if 1 < g < n: return int(g)
                z_accum = mpz(1)
            p = gmpy2.next_prime(p)

        g = gmpy2.gcd(z_accum, n)
        if 1 < g < n: return int(g)

        if (curve + 1) % 50 == 0:
            print(f"      ECM curve {curve+1}/{curves}...")
    return None


# ──────────────── RSA Decryption ─────────────────────

def decrypt_rsa(n, e, c):
    factors = factor_n(n)
    print(f"Factors: {factors}")
    prod = 1
    for p, exp in factors.items(): prod *= p ** exp
    assert prod == n, f"Factorization error!"
    phi = 1
    for p, exp in factors.items(): phi *= (p ** exp - p ** (exp - 1))
    d = pow(e, -1, phi)
    return pow(c, d, n)


# ──────────────────── Network ────────────────────────

def recv_until(sock, delim):
    data = b""
    while delim not in data:
        chunk = sock.recv(1)
        if not chunk: break
        data += chunk
    return data

def recv_line(sock):
    return recv_until(sock, b"\n")


# ──────────────────── Main ───────────────────────────

print("Connecting...")
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('chall.lac.tf', 31225))

# PoW
recv_line(sock)  # "proof of work:"
pow_cmd = recv_line(sock).decode().strip()
print(f"PoW: {pow_cmd}")
challenge = re.search(r's\.[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+', pow_cmd).group(0)
solution = solve_pow(challenge)
print("PoW solved.")
recv_until(sock, b"solution: ")
sock.sendall((solution + "\n").encode())

# RSA challenge
sock.setblocking(1)
sock.settimeout(10)
response = b""
try:
    while True:
        chunk = sock.recv(4096)
        if not chunk: break
        response += chunk
        if b"How many treats" in response: break
except socket.timeout:
    pass

text = response.decode()
print(text)

n = int(re.search(r'n = (\d+)', text).group(1))
e = int(re.search(r'e = (\d+)', text).group(1))
c = int(re.search(r'c = (\d+)', text).group(1))
print(f"n={n}\ne={e}\nc={c}\n")

m = decrypt_rsa(n, e, c)
print(f"\n*** m = {m} ***\n")

try:
    bl = (m.bit_length() + 7) // 8
    print(f"As text: {m.to_bytes(bl, 'big')}")
except: pass

sock.settimeout(10)
sock.sendall(f"{m}\n".encode())
try:
    flag = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk: break
        flag += chunk
except socket.timeout:
    pass
print("\n" + "=" * 50)
print(flag.decode())
sock.close()
