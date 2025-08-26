from Crypto.Util.number import getStrongPrime, inverse
import signal, random
signal.alarm(300)

def gen_param():
    p = getStrongPrime(1024)
    q = getStrongPrime(1024)
    return p * q, p, q 

def check_factor(n):
    print("input factors")
    u = int(input())
    v = int(input())
    assert 1 < u < n and 1 < v < n and u * v == n 

print("Let's go over some RSA basics for your CTF Journey!")

print("Challenge 1 : factor n from n and phi(n)")
n, p, q = gen_param()
phi = (p - 1) * (q - 1)
print("n = {}".format(n))
print("phi = {}".format(phi))
check_factor(n)

print("Challenge 2 : factor n from n and multiple of phi(n)")
n, p, q = gen_param()
phi = (p - 1) * (q - 1) * random.randint(1 << 1023, 1 << 1024)
print("n = {}".format(n))
print("phi = {}".format(phi))
check_factor(n)

print("Challenge 3 : attack with decryption oracle")
e = (1 << 16) + 1
n, p, q = gen_param()
while (p - 1) % e == 0 or (q - 1) % e == 0:
    n, p, q = gen_param()
phi = (p - 1) * (q - 1)
print("n = {}".format(n))
d = inverse(e, phi)
msg = random.randint(1, n)
enc = pow(msg, e, n)
print("encryption result = {}".format(enc))

target = int(input())
assert target != enc 
result = pow(target, d, n)
print("decryption result = {}".format(result))

final = int(input())
assert msg == final 

flag = open("flag", "r").read()
print(flag)