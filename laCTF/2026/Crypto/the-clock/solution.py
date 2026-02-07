from math import gcd, isqrt
from hashlib import md5
from Crypto.Cipher import AES
from functools import reduce
import sys
sys.setrecursionlimit(200000)

# ---- Known values ----
base_x = 13187661168110324954294058945757101408527953727379258599969622948218380874617
base_y = 5650730937120921351586377003219139165467571376033493483369229779706160055207

alice_x = 13109366899209289301676180036151662757744653412475893615415990437597518621948
alice_y = 5214723011482927364940019305510447986283757364508376959496938374504175747801

bob_x = 1970812974353385315040605739189121087177682987805959975185933521200533840941
bob_y = 12973039444480670818762166333866292061530850590498312261363790018126209960024

enc_flag = bytes.fromhex("d345a465538e3babd495cd89b43a224ac93614e987dfb4a6d3196e2d0b3b57d9")

# ---- Step 1: Recover p ----
v1 = base_x**2 + base_y**2 - 1
v2 = alice_x**2 + alice_y**2 - 1
v3 = bob_x**2 + bob_y**2 - 1
p = gcd(gcd(v1, v2), v3)

# Strip small prime factors
for sp in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
    while p % sp == 0:
        p //= sp

print(f"p = {p}")
print(f"p mod 4 = {p % 4}")

# ---- Clock curve operations ----
def clockadd(P1, P2):
    x1, y1 = P1
    x2, y2 = P2
    return (x1 * y2 + y1 * x2) % p, (y1 * y2 - x1 * x2) % p

def scalarmult(P, n):
    if n == 0:
        return (0, 1)
    if n < 0:
        x, y = P
        return scalarmult((-x % p, y), -n)
    if n == 1:
        return P
    Q = scalarmult(P, n >> 1)
    Q = clockadd(Q, Q)
    if n & 1:
        Q = clockadd(P, Q)
    return Q

# Iterative scalar mult for large n (avoid recursion limit)
def scalarmult_iter(P, n):
    if n == 0:
        return (0, 1)
    if n < 0:
        x, y = P
        P = (-x % p, y)
        n = -n
    R = (0, 1)  # identity
    Q = P
    while n > 0:
        if n & 1:
            R = clockadd(R, Q)
        Q = clockadd(Q, Q)
        n >>= 1
    return R

# ---- Step 2: Group order and factorization ----
# p ≡ 3 mod 4, so clock curve group order = p + 1
order = p + 1
factors = {
    2: 2, 39623: 1, 41849: 1, 42773: 1, 46511: 1, 47951: 1,
    50587: 1, 50741: 1, 51971: 1, 54983: 1, 55511: 1, 56377: 1,
    58733: 1, 61843: 1, 63391: 1, 63839: 1, 64489: 1
}

# Verify factorization
product = 1
for q, e in factors.items():
    product *= q ** e
assert product == order, f"Factorization mismatch: {product} != {order}"
print(f"Group order verified: {order}")

# ---- Step 3: Pohlig-Hellman with BSGS ----
base = (base_x % p, base_y % p)
alice_pub = (alice_x % p, alice_y % p)
bob_pub = (bob_x % p, bob_y % p)

def bsgs_clock(G, H, n):
    """Baby-step Giant-step: find k in [0, n) such that scalarmult(G, k) == H"""
    m = isqrt(n) + 1
    # Baby steps: table[scalarmult(G, j)] = j for j = 0..m-1
    table = {}
    cur = (0, 1)  # identity
    for j in range(m):
        table[cur] = j
        cur = clockadd(cur, G)
    # Giant step: G^(-m)
    G_neg_m = scalarmult_iter(G, (order - m) % order)  # inverse via order
    gamma = H
    for i in range(m):
        if gamma in table:
            k = (i * m + table[gamma]) % n
            return k
        gamma = clockadd(gamma, G_neg_m)
    return None

print("\nSolving DLP using Pohlig-Hellman...")
remainders = []
moduli = []

for q, e in factors.items():
    qe = q ** e
    exp = order // qe
    Gi = scalarmult_iter(base, exp)
    Hi = scalarmult_iter(alice_pub, exp)

    if e == 1:
        k = bsgs_clock(Gi, Hi, q)
    else:
        # Iterative Pohlig-Hellman for prime power
        k = 0
        Gq = scalarmult_iter(base, order // q)
        for j in range(e):
            exp_j = order // (q ** (j + 1))
            Gk_inv = scalarmult_iter(base, (order - k * exp) % order)
            Hj = clockadd(alice_pub, Gk_inv)
            Hj = scalarmult_iter(Hj, exp_j)
            dj = bsgs_clock(Gq, Hj, q)
            if dj is None:
                dj = 0
            k = k + dj * (q ** j)

    print(f"  k ≡ {k} (mod {qe})")
    remainders.append(k % qe)
    moduli.append(qe)

# ---- CRT ----
def crt(remainders, moduli):
    M = reduce(lambda a, b: a * b, moduli)
    x = 0
    for ri, mi in zip(remainders, moduli):
        Mi = M // mi
        yi = pow(Mi, -1, mi)
        x = (x + ri * Mi * yi) % M
    return x

alice_secret = crt(remainders, moduli)
print(f"\nAlice's secret = {alice_secret}")

# Verify
alice_check = scalarmult_iter(base, alice_secret)
assert alice_check == alice_pub, "DLP verification failed!"
print("DLP verified!")

# ---- Step 4: Compute shared secret and decrypt ----
shared = scalarmult_iter(bob_pub, alice_secret)
print(f"Shared secret: ({shared[0]}, {shared[1]})")

key = md5(f"{shared[0]},{shared[1]}".encode()).digest()
flag = AES.new(key, AES.MODE_ECB).decrypt(enc_flag)
print(f"\nFlag: {flag}")
