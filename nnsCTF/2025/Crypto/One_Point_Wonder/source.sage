from Crypto.Util.number import getPrime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import hashlib, os

A = 2^216
B = 3^137
p = A*B-1  
F.<i> = GF(p^2, modulus=[1,0,1])
E  = EllipticCurve(F, [1,0])

P, Q = (p+1)//B * E.random_point(), (p+1)//B * E.random_point()

n = getPrime(192)
R = P+n*Q
phi = E.isogeny(R, algorithm="factored")
E1 = phi.codomain()
phi_Q = phi(Q)  

flag = b"NNS{????????????????????????????????????????}"

iv = os.urandom(16)
cipher = AES.new(hashlib.sha256(str(n).encode()).digest(), AES.MODE_CBC, iv)
ct     = cipher.encrypt(pad(flag, 16)).hex()

print(f"j = {E1.j_invariant()}")
print(f"phi_Q = {phi_Q.xy()}")
print(f"Px = {P.x()}")
print(f"iv = 0x{iv.hex()}")
print(f"ct = 0x{ct}")