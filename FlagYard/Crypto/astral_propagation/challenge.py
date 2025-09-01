import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.strxor import strxor

MESSAGE = b'propagating cipher block chaining'

class Pcbc:
	def __init__(self, key):
		self.cipher = AES.new(key, AES.MODE_ECB)

	def encrypt(self, buf):
		buf = pad(buf, 16)
		iv = get_random_bytes(16)
		out = iv
		for i in range(0, len(buf), 16):
			p = buf[i:i+16]
			c = self.cipher.encrypt(strxor(iv, p))
			iv = strxor(p, c)
			out += c
		return out

	def decrypt(self, buf):
		iv = buf[:16]
		out = bytes()
		for i in range(16, len(buf), 16):
			c = buf[i:i+16]
			p = strxor(iv, self.cipher.decrypt(c))
			iv = strxor(p, c)
			out += p
		out = unpad(out, 16)
		return out

if __name__ == '__main__':
	key = secrets.token_bytes(16)
	cipher = Pcbc(key)
	while True:
		ct = bytes.fromhex(input('ciphertext (hex): '))
		try:
			msg = cipher.decrypt(ct)
			if msg == MESSAGE:
				print(open('flag.txt').read().strip())
			else:
				print('incorrect message')
		except Exception as e:
			print('failed to decrypt')
