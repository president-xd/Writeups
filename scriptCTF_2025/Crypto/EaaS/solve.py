from pwn import *

#io = process('./server.py')
io = remote("play.scriptsorcerers.xyz",10000)

# Receive
io.readuntil(b'Your Email is: ')
email=io.readline().strip().decode()

# Modify one byte of email and the expected domain
email=bytes.fromhex(hex(ord(email[0])^1)[2:])+email[1:].encode() 
payload=b'0'*16+b'a,'+email+b',0000000000000000@sbript.sorcerer' # Notice the sbript instead of script
payload=payload.hex()
io.sendline(payload.encode())

io.readuntil(b'Please use this key for future login: ')
ciphertext = bytes.fromhex(io.readline().strip().decode())
io.sendline(b'2')

# Split in groups so that each group has 16 bytes
group_1=ciphertext[:16]
group_2=ciphertext[16:32]
group_3=ciphertext[32:48]
group_4=ciphertext[48:64]
group_5=ciphertext[64:]

# Change the bytes that were modified earlier
byte = bytes.fromhex(hex(group_1[2]^1)[2:])
byte2 = bytes.fromhex(hex(group_4[2]^1)[2:]) 

to_send = group_1[:2]+byte+group_1[3:]+group_2+group_3+group_4[:2]+byte2+group_4[3:]+group_5
io.sendline(to_send.hex().encode())
io.sendline(b'1')
io.readuntil(b'Body: ')
flag=io.readline().strip().decode()
log.success('Flag: ' + flag)
