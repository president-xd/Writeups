import secrets

import ed25519

MESSAGE = b'gimme the flag'

if __name__ == '__main__':
	sk = secrets.token_bytes(16)
	pk = ed25519.publickey_unsafe(sk)
	print(f'pk (hex): {pk.hex()}')
	while True:
		command = input('command: ')
		if command == 'sign':
			msg = bytes.fromhex(input('message (hex): '))
			if msg == MESSAGE:
				print('invalid message')
			else:
				sig = ed25519.signature_unsafe(msg, sk, pk)
				print(sig.hex())
		elif command == 'verify':
			sig = bytes.fromhex(input('signature (hex): '))
			try:
				ed25519.checkvalid(sig, MESSAGE, pk)
				print("FlagY{this_is_a_fake_flag}")
				break
			except:
				print('invalid signature')
		else:
			break
