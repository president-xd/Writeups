from Crypto.Util.number import *
import signal, secrets, time
from secret import flag
from math import gcd

signal.alarm(12)

e = 65537

def find(a):
    while True:
        p = getPrime(a)
        q = getPrime(a)
        if gcd(e, (p-1)*(q-1)) == 1:
            n = p * q
            return n, p, q
        
for i in range(20, 30):
    n, p, q = find(i)
    m = secrets.randbelow(n-1) + 1
    c = pow(m, e, n)
    print(f'step {i - 19}')
    print(f'e = {e}')
    print(f'n = {n}')
    print(f'c = {c}')

    if int(input("> ").strip()) == m:
        time.sleep(0.01) # lol this is annoying
        continue
    else:
        print("Ewww")
        exit(0)

print(flag)