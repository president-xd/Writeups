import hashlib
import fastecdsa.curve
import random
def inv_mod(k, p):
    return pow(k, p - 2, p)

# secp256k1 parameters
curve = fastecdsa.curve.secp256k1
G = curve.G
n = curve.q

def sign(msg, k, d):
    z = int.from_bytes(hashlib.sha256(msg).digest(), 'big')
    R = G * k
    r = R.x % n
    s = (inv_mod(k, n) * (z + r * d)) % n
    return r, s

def verify(msg, signature, Q):
    r, s = signature
    if not (1 <= r < n and 1 <= s < n):
        return False
    z = int.from_bytes(hashlib.sha256(msg).digest(), 'big')
    w = inv_mod(s, n)
    u1 = (z * w) % n
    u2 = (r * w) % n
    R = G * u1 + Q * u2
    return R.x % n == r

key = open('flag.txt', 'rb').read()
d = int.from_bytes(key, 'big')
d = (d % (n - 1)) + 1 
P = G * d
k = random.randint(0, n - 1)

msgs = [
    b'Beware the Krampus Syndicate!',
    b'Santa is watching...',
    b'Good luck getting the key'
]
    
for m in msgs:
    r, s = sign(m, k, d)
    r_bytes = r.to_bytes(32, 'big')
    s_bytes = s.to_bytes(32, 'big')
    print(f'msg: {m}')
    print(f'r  : {r_bytes.hex()}')
    print(f's  : {s_bytes.hex()}')
    assert verify(m, (r, s), P)
    # gonna change nonces!
    k += 1