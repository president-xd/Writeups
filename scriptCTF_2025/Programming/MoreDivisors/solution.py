from pwn import *

n = 200000

context.log_level = 'error'

server = process(['python3', 'server.py'])

solver = process('./solution')
solver.send(server.recvline())

server.sendline(solver.recv())
print(server.recvline())
