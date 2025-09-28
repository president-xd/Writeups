from pwn import *
import time
from tqdm import tqdm

io = process(['python3','server.py'])
#io = remote("localhost",'1337')
io = remote("play.scriptsorcerers.xyz","10480")

grid = []
for x in tqdm(range(100)):
	nums = io.readline().strip().decode().split(' ')
	grid.append(' '.join(nums))
proc = subprocess.run(['./solution'], input='\n'.join(grid).encode(), stdout=subprocess.PIPE)
ans = proc.stdout.decode().strip()
print(ans.split('\n'))
for line in ans.split('\n'):
    io.sendline(line.encode())
print(io.recv())
