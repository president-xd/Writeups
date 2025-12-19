import secrets, math, struct, hashlib
from decimal import getcontext, Decimal as D
getcontext().prec = 28
xor = lambda A, B: bytes([a ^ b for a, b in zip(A, B)])


class RealNumberGenerator():
    def __init__(self, seed):
        self.state = seed

    def random(self):
        self.state = D(math.e) * D(self.state) % D(math.pi)
        return math.sqrt(math.fabs(math.sin(D(self.state)) + math.cos(D(self.state))))

    def next_bytes(self):
        while True:
            r = self.random()
            B = struct.pack('d', r)
            for b in B:
                yield b


def main():
    seed = secrets.randbits(48)
    rng = RealNumberGenerator(seed)
    flag = open('flag.txt', 'rb').read().strip()

    msg = b'The flag is: ' + xor(flag, hashlib.shake_256(str(seed).encode()).digest(len(flag)))
    enc = xor(msg, rng.next_bytes())
    print(enc.hex())


if __name__ == '__main__':
    main()
