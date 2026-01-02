# Solution for multi-prime RSA with known seed
# Run with: sage solution_multiprime.sage

# Reproduce the exact same random selection
set_random_seed(777)

p = list(prime_range(11, 8296))
primes = sample(p, 777)

n = prod(primes)
phi = prod(p - 1 for p in primes)

e = 65537
d = inverse_mod(e, phi)

# Read ciphertext from output.txt (adjust path as needed)
# Format: e = ..., n = ..., c = ... on separate lines
with open("output.txt", "r") as f:
    lines = f.readlines()
    # e_val = int(lines[0].split('=')[1].strip())  # Should be 65537
    # n_val = int(lines[1].split('=')[1].strip())  # Should match our n
    c = int(lines[2].split('=')[1].strip())        # The ciphertext

# Verify our n matches
# assert n == n_val, "n doesn't match!"

# Decrypt
m = pow(c, d, n)

# Convert to bytes
flag_bytes = int(m).to_bytes((int(m).bit_length() + 7) // 8, 'big')
print(f"Flag: {flag_bytes.decode()}")
