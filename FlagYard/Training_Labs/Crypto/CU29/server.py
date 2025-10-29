from Crypto.Util.number import getPrime
import random
from math import gcd
from random import randint
e=23
while True:
    p=getPrime(512)
    q=getPrime(512)
    n=p*q
    phi=(p-1)*(q-1)
    print(1)
    if (p-1) % e == 0 or (q-1)%e ==0:
        break
while True:
	try:
		d = randint(0, int(n**0.34))
		ee=pow(d,-1,phi)
		break
	except:
		continue
n
flag="redacted"
m = int.from_bytes(flag.encode(), 'big')
c = pow(m, e, n)

print(f"{n = }")
print(f"{e = }")
print(f"{c = }")
print(f"pq= {(p+q)>>200}")
print(f"{ee = }")