import numpy as np
from binteger import Bin
from Crypto.Hash import SHAKE128
from random import SystemRandom

shake = SHAKE128.new(b'defund')
random = SystemRandom()

n = 976
sigma = 2.3

crs = shake.read(np.dtype(np.uint16).itemsize * n**2)
A = np.frombuffer(crs, dtype=np.uint16).reshape((n, n))

def gaussian():
	return np.fromfunction(np.vectorize(lambda *_: round(random.gauss(0, sigma))), (n,)).astype(np.uint16)

def keygen():
	s = gaussian()
	pk = s @ A + 2*gaussian()
	sk = np.append(-s, 1).astype(np.uint16)
	return pk, sk

def encrypt(pk, b):
	e = gaussian()
	return np.append(A @ e, pk @ e + b).astype(np.uint16)

def decrypt(sk, c):
	return sk.dot(c) & 1

if __name__ == '__main__':
	with open('flag.txt', 'rb') as f:
		flag = f.read().strip()

	pk, sk = keygen()

	with open('pk', 'wb') as f:
		f.write(pk.tobytes())

	with open('ct', 'wb') as f:
		for b in Bin(flag):
			c = encrypt(pk, b)
			f.write(c.tobytes())
