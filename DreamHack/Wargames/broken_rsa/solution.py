from Crypto.Util.number import *
from math import gcd

# =========================
# Given values
# =========================

N = 8664641723957572832312779742030628394181341342591923969297731209808057699227840198922331702627263901272777045757804172982633603108280840828287254107452347
e = 65537
c = 1199859467743185735052169484711258292775193393950322390969458108983012972002533082877753909987345514084073979369072583808459033801607498441514100466423094

leaks = [
    13827883242149747916,
    15009501110563849515,
    9175221269988376286,
    13566727083203326037,
    8258163756964211520
]

MOD = 2**64

# =========================
# Step 1: Recover LCG
# =========================

def inv(x):
    return pow(x, -1, MOD)

x0, x1, x2 = leaks[0], leaks[1], leaks[2]
a = ((x2 - x1) * inv(x1 - x0)) % MOD
c_lcg = (x1 - a*x0) % MOD

print("[+] LCG recovered")
print("a =", a)
print("c =", c_lcg)

# =========================
# Step 2: Regenerate LCG states (extend backwards and forwards)
# =========================

# Start with the leaked states
states = list(leaks)

# Extend forward from the last leak
x = leaks[-1]
for _ in range(50):
    x = (a*x + c_lcg) % MOD
    states.append(x)

# Extend backward from the first leak
a_inv = inv(a)
x = leaks[0]
backward_states = []
for _ in range(20):
    x = (a_inv * (x - c_lcg)) % MOD
    backward_states.append(x)

# Combine: backward states (reversed) + original states
all_states = backward_states[::-1] + states

# =========================
# Step 3: Prime generator
# =========================

def next_prime_py(n):
    if n % 2 == 0:
        n += 1
    while not isPrime(n):
        n += 2
    return n

def build_prime(state_list, i):
    val = 0
    for j in range(4):
        val = (val << 64) | state_list[i + j]
    return next_prime_py(val)

# =========================
# Step 4: Recover p and q
# =========================

print("[+] Searching for p and q...")

p = q = None

for i in range(len(all_states) - 8):
    P = build_prime(all_states, i)
    if N % P == 0:
        p = P
        q = N // P
        print(f"[+] Found at index {i}")
        break

if p is None:
    raise Exception("[-] Failed to recover primes")

print("[+] p =", p)
print("[+] q =", q)

# =========================
# Step 5: Decrypt
# =========================

phi = (p - 1) * (q - 1)
d = inverse(e, phi)
m = pow(c, d, N)

flag = long_to_bytes(m)

print("\n[+] Decrypted message:")
print(flag)
