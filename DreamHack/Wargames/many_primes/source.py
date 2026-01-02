set_random_seed(777) 

p = list(prime_range(11, 8296))

primes = sample(p, 777) 

n = prod(primes)

phi = prod(p - 1 for p in primes)

e = 65537

d = inverse_mod(e, phi)

flag = "DH{REDACTED}"
mb = flag.encode('utf-8')
m = int.from_bytes(mb, 'big')

c = pow(m, e, n)

print(e)
print(n)
print(c)