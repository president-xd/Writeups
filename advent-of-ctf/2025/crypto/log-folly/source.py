from Crypto.Util.number import getPrime, bytes_to_long
from secret import FLAG

def rotate(s):
    return s[1:] + s[:1]

p = getPrime(256)
g = 2

print('p: ', p)
for _ in range(len(FLAG)):
    x = bytes_to_long(FLAG.encode())
    h = pow(g, x, p)
    print('leak: ', h)
    FLAG = rotate(FLAG)
