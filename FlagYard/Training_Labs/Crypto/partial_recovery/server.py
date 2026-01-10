from Crypto.Util.number import getPrime, GCD, bytes_to_long
from random import randint


FLAG = str(os.getenv('DYN_FLAG')).encode()
class Crypto:
    def __init__(self, bits):
        self.bits = bits
        self.alpha = 16
        self.delta = 1/4
        self.known = int(self.bits*self.delta)
        print(self.known)
        
    
    def keygen(self):
        while True:
            p, q = [getPrime(self.bits//2) for _ in '__']
            self.e = getPrime(int(self.alpha))
            φ = (p-1)*(q-1)
            try:
                dp = pow(self.e, -1, p-1)
                dq = pow(self.e, -1, q-1)
                self.n = p*q
                break
            except:
                pass

        return (self.n, self.e), (dp, dq)

    def encrypt(self, m):
        return pow(m, self.e, self.n)

rsa = Crypto(2048)
_, (dp, dq) = rsa.keygen()

m = bytes_to_long(FLAG)
c = rsa.encrypt(m)

with open('output.txt', 'w') as f:
    f.write(f'N = 0x{rsa.n:x}\n')
    f.write(f'e = 0x{rsa.e:x}\n')
    f.write(f'c = 0x{c:x}\n')
    print(dp)
    print(dp.bit_length())
    f.write(f'dp = 0x{(dp % 2**(512)):x}\n')
    f.write(f'dq = 0x{(dq % 2**(512)):x}\n')
  #  f.write(f'TWO_POWER = 0x{( 2**(256))):x}\n')
