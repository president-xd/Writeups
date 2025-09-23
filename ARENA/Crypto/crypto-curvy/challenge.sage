#!/usr/bin/sage -python

from sage.all import *
from hashlib import sha512
from random import randint

def get_flag():
    try:
        with open("flag.txt", "r") as f:
            FLAG = f.read().strip()
        return FLAG
    except:
        print("[ERROR] - Please contact an Administrator.")

n = 0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409
h = 0x1
p = 0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
K = GF(p)
a = K(0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc)
b = K(0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00)
E = EllipticCurve(K, (a, b))
G = E(0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66, 0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650)
E.set_order(n * h)
k = randint(1, E.order()-1)
d = randint(1,n-1)

def sign():
    verify = 'IdkJusTcalculateHash'
    msg = input("Enter the message: ")
    if verify in msg:
        print("NOPE")
        return
    m = int(sha512(msg.encode()).hexdigest(), 16)
    Q = k*G
    r = int(Q[0]) % n
    s = (pow(k, -1, n) * (m + r * d)) % n
    print("Signature: " + str(r) + " " + str(s))

def flag():
    m = 'IdkJusTcalculateHash'
    _m = int(sha512(m.encode()).hexdigest(), 16)
    Q = k*G
    r = int(Q[0]) % n
    s = (pow(k, -1, n) * (_m + r * d)) % n
    r_in = int(input("Enter r: "))
    s_in = int(input("Enter s: "))
    assert r == r_in and s == s_in, "Invalid signature"
    print(f"Good boiii: {get_flag()}")

if __name__ == "__main__":
    while True:
        print("1. Sign")
        print("2. Get flag")
        choice = int(input("Enter your choice: "))
        if choice == 1:
            sign()
        elif choice == 2:
            flag()
        else:
            break