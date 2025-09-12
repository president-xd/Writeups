from Crypto.Util.number import *
from random import *
flag = b'FlagY{*********************}'

def int_to_ternary(n):
    if n == 0:
        return [0]
    digits = []
    while n:
        digits.append(n % 3)
        n = n // 3
    return digits[::-1]

flag = flag.strip(b"FlagY{").strip(b"}")
flag_int = bytes_to_long(flag)
flag_ternary = int_to_ternary(flag_int)

g = 2
length = len(flag_ternary)
p = getPrime(1024)
q = getPrime(1024)
n = p*q
bag = flag_ternary
A = [randint(1, n-1) for _ in range(length)]

s = 1
for i in range(length):
    s *= pow(g, (bag[i] * A[i]), n**2)
    s %= n**2

with open("output.txt", "w") as f:
    f.write(f"p = {p}\n")
    f.write(f"q = {q}\n")
    f.write(f"gA = {[pow(g, a, n**2) for a in A]}\n")
    f.write(f"s = {s}\n")
