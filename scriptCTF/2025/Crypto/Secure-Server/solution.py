from pwn import xor 

# Got from Wireshark
t1 = bytes.fromhex("151e71ce4addf692d5bac83bb87911a20c39b71da3fa5e7ff05a2b2b0a83ba03")

# Got from Wireshark
t2 = bytes.fromhex("e1930164280e44386b389f7e3bc02b707188ea70d9617e3ced989f15d8a10d70")

# Got from Wireshark
t3 = bytes.fromhex("87ee02c312a7f1fef8f92f75f1e60ba122df321925e8132068b0871ff303960e")

print(xor(xor(t1,t2),t3).decode())