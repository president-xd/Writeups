from pwn import remote
from Crypto.Util.number import long_to_bytes
import re
import random

# ======================
# FILL THESE PARAMETERS
# ======================
# Copy these from the challenge's secret / description
p  = ...        # prime modulus
a  = ...        # curve parameter a
b  = ...        # curve parameter b
gx = ...        # g[0]
gy = ...        # g[1]

L_BITS = 8      # matches challenge


# ======================
# EC arithmetic over F_p
# ======================

def inv_mod(x, p):
    return pow(x, p - 2, p)


class ECPoint:
    """Simple elliptic curve point over F_p: y^2 = x^3 + a x + b"""

    def __init__(self, x, y, inf=False):
        self.x = x
        self.y = y
        self.inf = inf  # point at infinity flag

    def is_inf(self):
        return self.inf

    def __neg__(self):
        if self.inf:
            return self
        return ECPoint(self.x, (-self.y) % p)

    def __add__(self, other):
        if self.inf:
            return other
        if other.inf:
            return self

        # P + (-P) = O
        if self.x == other.x and (self.y + other.y) % p == 0:
            return ECPoint(0, 0, True)  # infinity

        if self.x == other.x and self.y == other.y:
            # point doubling
            s = (3 * self.x * self.x + a) * inv_mod(2 * self.y % p, p) % p
        else:
            # point addition
            s = (other.y - self.y) * inv_mod((other.x - self.x) % p, p) % p

        rx = (s * s - self.x - other.x) % p
        ry = (s * (self.x - rx) - self.y) % p
        return ECPoint(rx, ry)

    def __sub__(self, other):
        return self + (-other)

    def mul(self, k: int):
        """Scalar multiplication k * P via double-and-add (no order needed)."""
        if k == 0 or self.inf:
            return ECPoint(0, 0, True)
        result = ECPoint(0, 0, True)  # infinity
        addend = self
        while k > 0:
            if k & 1:
                result = result + addend
            addend = addend + addend
            k >>= 1
        return result

    def __repr__(self):
        if self.inf:
            return "ECPoint(infinity)"
        return f"ECPoint({self.x}, {self.y})"


def main():
    # --- connect to remote ---
    r = remote("tcp.flagyard.com", 23502)

    # read until we see the line with ct=
    banner = b""
    while b"ct=" not in banner:
        line = r.recvline()
        banner += line

    # extract ct=(...)
    m = re.search(rb"ct=\(([^)]*)\)", banner)
    if not m:
        print("[-] Couldn't find ct= in banner")
        return

    nums = list(map(int, m.group(1).split(b",")))
    if len(nums) != 4:
        print("[-] Unexpected ct length")
        return

    c1x, c1y, c2x, c2y = nums
    print("[*] Got ct:")
    print("    c1x =", c1x)
    print("    c1y =", c1y)
    print("    c2x =", c2x)
    print("    c2y =", c2y)

    # --- rebuild base point and ciphertext points ---
    G  = ECPoint(gx, gy)
    C1 = ECPoint(c1x, c1y)
    C2 = ECPoint(c2x, c2y)

    # --- choose random R = r * G and compute C2' = C2 + R ---
    while True:
        # 256-bit random scalar is plenty
        r_scalar = random.getrandbits(256)
        if r_scalar == 0:
            continue
        R = G.mul(r_scalar)
        C2_prime = C2 + R

        # avoid hitting filters: same C2.x or C2.y as original
        if C2_prime.x != c2x and C2_prime.y != c2y:
            break

    c2x_p = C2_prime.x
    c2y_p = C2_prime.y

    print("[*] Crafted modified ciphertext (reuse C1, tweak C2):")
    print(f"    ({c1x},{c1y},{c2x_p},{c2y_p})")

    # --- menu: choose 2 (dec), send modified ct ---
    data = b""
    while b">>" not in data:
        data += r.recv(1)

    r.sendline(b"2")  # dec
    r.recvuntil(b"ciphertext>>")
    payload = f"{c1x},{c1y},{c2x_p},{c2y_p}".encode()
    r.sendline(payload)

    # read until "m= " or an error message
    line = r.recvline()
    while b"m=" not in line and b"bad ciphertext" not in line and b"not that easy" not in line:
        line = r.recvline()

    print("[*] Oracle response:", line.strip())

    if b"bad ciphertext" in line or b"not that easy" in line:
        print("[-] Oracle rejected this attempt, just run solve.py again (new R).")
        r.close()
        return

    # parse: m=  mx my
    m_part = line.split(b"m=")[1].strip()
    mx_bytes, my_bytes = m_part.split()
    mx = int(mx_bytes)
    my = int(my_bytes)

    # --- reconstruct M' = M + R, then M = M' - R ---
    M_plus_R = ECPoint(mx, my)
    M = M_plus_R - R

    x_M = M.x
    m_int = x_M >> L_BITS
    flag = long_to_bytes(m_int)

    print("[+] Recovered message integer m_int =", m_int)
    print("[+] FLAG bytes:", flag)
    try:
        print("[+] FLAG string:", flag.decode())
    except UnicodeDecodeError:
        print("[+] FLAG is not nice UTF-8, raw bytes above.")

    r.close()


if __name__ == "__main__":
    main()
