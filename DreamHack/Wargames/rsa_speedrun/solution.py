from pwn import *
from sympy import factorint
from Crypto.Util.number import inverse

# Connect to the challenge
r = remote('host8.dreamhack.games', 16849)
# r = process(['python', 'prob.py'])  # For local testing

e = 65537

for step in range(1, 11):
    # Parse the output
    r.recvuntil(b'step ')
    r.recvline()  # step number
    r.recvline()  # e = ...
    n_line = r.recvline().decode()
    c_line = r.recvline().decode()
    
    n = int(n_line.split('=')[1].strip())
    c = int(c_line.split('=')[1].strip())
    
    # Factor n (trivial for 40-60 bit numbers)
    factors = factorint(n)
    primes = list(factors.keys())
    p, q = primes[0], primes[1]
    
    # Compute private key and decrypt
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    m = pow(c, d, n)
    
    # Send answer
    r.sendlineafter(b'> ', str(m).encode())
    print(f"[+] Step {step} done: m = {m}")

# Get flag
flag = r.recvline().decode()
print(f"[*] Flag: {flag}")
