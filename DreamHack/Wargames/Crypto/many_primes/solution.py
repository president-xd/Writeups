# Python version (no SageMath needed)
# Uses sympy for prime generation and reproduces Sage's random with same seed

from functools import reduce
from operator import mul

# Sage's set_random_seed(777) uses a specific PRNG
# We need to replicate the exact prime selection

# First, get all primes in range [11, 8296)
def sieve_primes(start, end):
    sieve = [True] * end
    sieve[0] = sieve[1] = False
    for i in range(2, int(end**0.5) + 1):
        if sieve[i]:
            for j in range(i*i, end, i):
                sieve[j] = False
    return [i for i in range(start, end) if sieve[i]]

primes_list = sieve_primes(11, 8296)
print(f"[*] Total primes in range: {len(primes_list)}")

# The trick: Sage's sample() with seed 777 produces deterministic output
# We can just run this in Sage to get the primes, or hardcode them

# Actually, the easiest way is to just run Sage code
# But here's a pure Python approach using Sage's random algorithm

# For production, run this SageMath one-liner to get primes:
# sage -c "set_random_seed(777); p=list(prime_range(11,8296)); print(sample(p,777))"

# Or use the sage script. Here's Python code assuming we have the primes:

def solve_with_primes(selected_primes, c):
    n = reduce(mul, selected_primes)
    phi = reduce(mul, (p - 1 for p in selected_primes))
    e = 65537
    d = pow(e, -1, phi)
    m = pow(c, d, n)
    flag_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')
    return flag_bytes.decode()

# Read output.txt (from same directory as script)
import os
script_dir = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(script_dir, "output.txt"), "r") as f:
    lines = [line.strip() for line in f.readlines() if line.strip()]
    e = int(lines[0].split('=')[1].strip())
    n = int(lines[1].split('=')[1].strip())
    c = int(lines[2].split('=')[1].strip())

print(f"[*] e = {e}")
print(f"[*] n has {n.bit_length()} bits")
print(f"[*] c has {c.bit_length()} bits")

# Factor n by trial division with small primes (we know all factors are < 8296)
print("[*] Factoring n with trial division...")
found_primes = []
temp_n = n
for p in primes_list:
    if temp_n % p == 0:
        found_primes.append(p)
        temp_n //= p
        if temp_n == 1:
            break

print(f"[*] Found {len(found_primes)} prime factors")

if temp_n == 1:
    flag = solve_with_primes(found_primes, c)
    print(f"[*] Flag: {flag}")
else:
    print(f"[!] Remaining unfactored: {temp_n}")
