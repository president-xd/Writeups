import hashlib 
import signal
from Crypto.Util.number import getStrongPrime, long_to_bytes, bytes_to_long, isPrime

signal.alarm(300)

p = getStrongPrime(1024)
q = getStrongPrime(1024)
n = p * q
phi = (p - 1) * (q - 1)
g = 3

print("modulus is {}".format(n))

result = pow(g, pow(2, 1 << 256, phi), n)
print("in Z_n, g^(2^(2^256)) == {}".format(result))

h = int(input()) 

assert 1 < h < n - 1
assert h != result, "no obvious proofs please, haha"

def genRandomPrime(modulus, base, claim):
    idx = 0
    while True:
        val = bytes_to_long(hashlib.sha256(long_to_bytes(modulus) + long_to_bytes(base) + long_to_bytes(claim) + long_to_bytes(idx)).digest()) % (1 << 40)
        if isPrime(val):
            return val 
        idx += 1

l = genRandomPrime(n, g, h)
print("my challenge is {}".format(l))

proof = pow(g, pow(2, 1 << 256, l * phi) // l, n)
print("the correct proof is {}".format(proof))

pi = int(input())

assert 1 < pi < n - 1
assert pi != proof, "no obvious proofs please, haha"

r = pow(2, 1 << 256, l)
assert result % n == (pow(proof, l, n) * pow(g, r, n)) % n 

if h % n == (pow(pi, l, n) * pow(g, r, n)) % n:
    print("proof success! here's your flag")
    flag = open("flag", "r").read()
    print(flag)
else:
    print("oops")