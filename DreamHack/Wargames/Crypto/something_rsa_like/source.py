from Crypto.Util.number import getPrime, bytes_to_long
from math import gcd
import secrets
from secret import flag

e = 65537

flag = bytes_to_long(flag)

while True:
    p, q = getPrime(512), getPrime(512)
    n = p * q
    lam = gcd(p - 1, q - 1)
    if gcd(lam, n) == 1:
        break

def L(x: int) -> int:
    return (x - 1) // n

mu = pow(L(pow(n + 1, lam, n**2)), -1, n)

while True:
    r = secrets.randbelow(n)
    if 1 <= r < n and gcd(r, n) == 1:
        break

n2 = n ** 2

def enc(m):
    if m > n:
        return "Too big"
    gm = (1 + m * n) % n2
    rn = pow(r, n, n2)
    c = (gm * rn) % n2
    return c

def dec(c):
    x = pow(c, lam, n2)
    m = (L(x) * mu) % n
    return m

print(f"{n = }")
print(f"{e = }")
print(f"{enc(flag) = }")

m = bytes_to_long(input("> ").encode())
print(enc(m))
c = int(input("> "))
print(dec(c))