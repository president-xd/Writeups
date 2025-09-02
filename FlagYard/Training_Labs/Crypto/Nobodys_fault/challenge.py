from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
from hashlib import sha256
import os

FLAG = b"FlagY{example_flag_goes_here}"  


p = getPrime(512)
q = getPrime(512)
n = p * q
e = 65537

d=pow(e,-1,p-1)


	
while True:
	print("=== RSA Signature Service ===")
	print("1. Sign a message")
	print("2. Verify a signature")
	print("3. Encrypt a message")
	print("")
	try:
		choice = input("> ").strip()
		if choice == "1":
			msg = input("Message to sign: ").encode()
			h = bytes_to_long(sha256(msg).digest())
			sig = pow(h, d, p)  
			print(f"Signature: {sig}")
		elif choice == "2":
			msg = input("Message: ").encode()
			sig = int(input("Signature: "))
			h = bytes_to_long(sha256(msg).digest())
			check = pow(sig, e, n)
			if check == h :
				print("Valid signature!")
				if msg==b'give_me_flag':
					print(f"Here is your flag: {FLAG.decode()}")
			else:
				print("Invalid signature.")
		if choice == "3":
			msg = bytes_to_long(input("Message to encrypt: ").encode())
			enc = pow(msg, e, q)
			print(f"enc: {enc}")
		
		else:
			print("Invalid option.")
	except Exception :
		print(f"Error")