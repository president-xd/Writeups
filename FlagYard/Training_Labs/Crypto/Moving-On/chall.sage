from Crypto.Util.number import bytes_to_long
from Crypto.Util.Padding import pad

p = 0x00e675aaef519c7bdfa7e9b6d5  
a = 0x00c5a83d2b9ce92d9c75a37a08
b = 0x0020cd6dc3b4b34e4332463ccd

E = EllipticCurve(GF(p), [a, b])
G = E.gens()[0]

flag = pad(open("flag.txt", "rb").readline().strip(), 12)

secrets = [flag[i:i+12] for i in range(0, len(flag), 12)]
secrets = [bytes_to_long(secret) for secret in secrets]

Qs = [secret * G for secret in secrets]
print(Qs)


"""
Q1 = (25868279382606376233089622039, 35226758373642087968613953852)
Q2 = (31211278741961598848732755066, 68653856268530027481128223450)
"""