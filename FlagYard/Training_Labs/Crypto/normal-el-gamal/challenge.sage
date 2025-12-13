from Crypto.Util.number import bytes_to_long, long_to_bytes
import random
from secret import p, n, g, a, b, FLAG

L_BITS = 8
MAX_COUNTER = 1 << L_BITS

class TotallyNormalElGamal:
    def __init__(self, n, p, g, a, b):
        self.n = n
        self.p = p
        self.a = a
        self.b = b
        self.x = random.randint(1, n-1)
        self.y = random.randint(1, n-1)
        
        self.E = EllipticCurve(GF(p), [a, b])
        self.G = self.E(g[0], g[1])
        
        self.A = self.x * self.G
        self.B = self.y * self.G
        
    def _map_to_point(self, m):
        Fp = GF(p)
        a_field = Fp(self.a)
        b_field = Fp(self.b)
        for ctr in range(MAX_COUNTER):
            x_val = (m << L_BITS) + ctr
            if x_val >= p:
                break
            x_elem = Fp(x_val)
            rhs = x_elem**3 + a_field * x_elem + b_field
            if legendre_symbol(int(rhs), p) == 1:
                y_elem = rhs.sqrt()
                return self.E(x_elem, y_elem)
        raise ValueError("Cannot encode message as curve point")
    
    def _point_to_int(self, P):
        x_val = int(P.xy()[0])
        m_int = x_val >> L_BITS
        return m_int
        
    def enc(self, m):
        m = self._map_to_point(m)
        k = random.randint(1, n-1)
        C1 = k * self.G
        C2 = k * self.A + m
        return (C1[0], C1[1], C2[0], C2[1])
    
    def dec(self, C):
        C1, C2 = (C[0], C[1]), (C[2], C[3])
        C1 = self.E(C1[0], C1[1])
        C2 = self.E(C2[0], C2[1])
        m = C2 - self.x * C1
        return m

Menu = """
1. enc (int)
2. dec (c1x, c1y, c2x, c2y)
3. Exit
"""

def main():
    elgamal = TotallyNormalElGamal(n, p, g, a, b)
    flag = bytes_to_long(FLAG.encode())
    
    ct = elgamal.enc(flag)
    print(f"{ct=}")
    
    print("Welcome to the Totally Normal ElGamal Oracle!")
    
    while True:
        print(Menu)
        choice = input(">>")
        if choice == '1':
            pt = input("plaintext>> ")
            try:
                pt = int(pt)
            except Exception:
                print("bad plaintext")
                continue
            ct2 = elgamal.enc(pt)
            print(ct2)
        elif choice == '2':
            ct2 = input("ciphertext>> ")
            
            try:
                ct2 = ct2.split(",")
                for i in range(4):
                    ct2[i] = int(ct2[i])
                ct2 = (ct2[0], ct2[1], ct2[2], ct2[3])
            except Exception:
                print("bad ciphertext")
                continue
            
            if ct2 == ct or ct2[2] == ct[2] or ct2[3] == ct[3]:
                print("not that easy")
                continue
            
            try:
                decrypted_text = elgamal.dec(ct2)
            except:
                print("bad ciphertext")
                continue
            
            if elgamal._point_to_int(decrypted_text) == bytes_to_long(FLAG.encode()):
                print("not that easy")
                continue
            
            print("m= ", decrypted_text[0], decrypted_text[1])
        elif choice == '3':
            print("Byee!")
            break
        else:
            print("read the options")

    
    
if __name__ == "__main__":
    main()
        
        
