from Crypto.Util.number import *
import signal, os, time, random
from secret import flag
from math import gcd

e = 65537

l_n = []
l_m = []
l_c = []
l_h = []
l = 0

print("Plz Wait...", flush=True)
while l < 10:
    p = getPrime(2048)
    q = getPrime(2048)
    if q > p:
        p, q = q, p
    if gcd(e, (p-1)*(q-1)) == 1:  
        m = bytes_to_long(os.urandom(64))
        n = p * q
        h = p - q
        c = pow(m, e, n)
        l_n.append(n)
        l_m.append(m)
        l_c.append(c)
        l_h.append(h)
        l = l + 1

print("Okay, Let's go!")
time.sleep(1)
signal.alarm(5)

for i in range(10):
    print(f"step {i + 1}")
    print(f'e = {e}')
    print(f'n = {l_n[i]}')
    print(f'c = {l_c[i]}')
    print(f'hint = {l_h[i]}')
    if int(input("> ")) == l_m[i]:
        continue
    else:
        print("Ewww")
        exit(0)

print(pow(bytes_to_long(flag), e, l_n[random.randint(0, 9)]))     