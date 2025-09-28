from Crypto.Util.number import getPrime, bytes_to_long
from Crypto.Util.Padding import pad

FLAG = open("flag.txt", "rb").read().strip()
m = bytes_to_long(pad(FLAG, 64))
e = 3
keys = []

with open("output.txt", "w") as f:
    for i in range(3):
        p = getPrime(512)
        q = getPrime(512)
        n = p * q
        c = pow(m, e, n)
        keys.append((n, c))
        f.write(f"n{i+1} = {n}\n")
        f.write(f"c{i+1} = {c}\n\n")

    f.write(f"e = {e}\n")
