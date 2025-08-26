from Crypto.PublicKey import RSA
from hashlib import sha256

with open('flag.txt', 'rb') as f:
	flag = f.read().strip()

key = RSA.generate(2048)

m = int.from_bytes(flag, 'big')
c = pow(m, key.e, key.n)

msg = b'an arbitrary message'
h = int.from_bytes(sha256(msg).digest(), 'big')

s1 = pow(h, int(key._dp), key.p)
s2 = pow(h, int(key._dq), key.q)

with open('out.txt', 'w') as f:
	f.write('Public parameters:\n')
	f.write(f'n = {key.n}\n')
	f.write(f'e = {key.e}\n')
	f.write('Encrypted message:\n')
	f.write(f'c = {c}\n')
	f.write('Partially signed message:\n')
	f.write(f'msg = {msg}\n')
	f.write(f's1 = {s1}\n')
	f.write(f's2 = {s2}\n')
