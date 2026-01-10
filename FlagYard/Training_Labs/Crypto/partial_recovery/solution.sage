#!/usr/bin/env sage
"""
Solution for partial_recovery challenge

Based on paper: "Factoring with Only a Third of the Secret CRT-Exponents"
https://eprint.iacr.org/2022/271.pdf

We have LOWER 512 bits of dp and dq.
Standard small_roots fails at this theoretical boundary - need custom lattice.
"""

from Crypto.Util.number import long_to_bytes
import itertools

# Challenge data
N = 0xa9f20f8f48075f4abdb1fa55732929e7d70b9ac089abf54ef5896e1e6e3228447be14f9fac2c11a943f4924361d8ff18e19e6314f12662de77480dfe17cfd0479453ba96aee5dc5b12db822b0507d4a49e1d132e062748fa673ac39c2c22cfa38a1f710de2e20c23eb679a70734028851f0a00c522949072d0dae9712f507a13dad2339863fc6c3c3af613995b05fdefb9508ce35434595caea355e331c22b9914dcbe4407ec7f16d2c8fd04465778ed628012f444642a28c85c68e72438c8a7aa0d0079a7eab54faa390fa4c840a45ded2971dd63c444b54063cdfe177fde1cc8cf90fe6d81df297e519f9abd349dfea238b008ba486b4015dcc32e24f8cc03
e = 0xa4ff
c = 0xf6a7384a558ec0dfe3ef1739a7dba5d301c4b1a11774d48c9d20bee85b052f03a4a86b799cc8e99c236ca1126dd5c8b20eb3261691498aef0472569fca6727b8d1d35aa41ae26639f555175d50bcc9c1c64c0fe74a6f7b33226d944d5673e85a2185a9c9d8807bbbde6e70d564b7a29e1d6c6639c028d78f0ab5f57f10867a07f4280ec22b346169cb572e486689b16423ca43f0c5bdf33e0ea093cb54d75d4a28177c6f8ac85390dbc2774589e213456beab117f3f2d08446badb56831b5fe0943d188006803b75726a0b0c0ff3f12ae94164175885457e9be3b09533df55ede2337257e73a602b7922a08b0774705d4dd67e9a1131fbc0b2ae1d38554a245
dp_low = 0x6d97285825b1ca3a329159ce9ad24cd12766ea83ff50ad3af807ef023bca7a99c03d71a7e819486e15284285c7f962d4e3ae0a068c05e66b2721bb810b763a5d
dq_low = 0xfb1e95fe13737b13404783341dd3adb1c1a6bc11de2993e3db8d7b67274724c67bdf9d6988b1b9065f4427fcb3e523cec5baad41d005026c7b70ee4908c9a4d7

KNOWN_BITS = 512
MOD = 2^KNOWN_BITS

print(f"N = {N.bit_length()} bits")
print(f"e = {e} ({e.bit_length()} bits)")

# Bivariate Coppersmith for finding k, l
def defund_multivariate(f, bounds, m=1, d=None):
    if not d:
        d = f.degree()
    R = f.base_ring()
    N_mod = R.cardinality()
    f = f.change_ring(ZZ)
    G = Sequence([], f.parent())
    for i in range(m+1):
        base = N_mod^(m-i) * f^i
        for shifts in itertools.product(range(d), repeat=f.nvariables()):
            g = base * prod(map(power, f.variables(), shifts))
            G.append(g)
    B, monomials = G.coefficients_monomials()
    monomials = vector(monomials)
    factors = [monomial(*bounds) for monomial in monomials]
    for i, factor in enumerate(factors):
        B.rescale_col(i, factor)
    B = B.dense_matrix().LLL()
    B = B.change_ring(QQ)
    for i, factor in enumerate(factors):
        B.rescale_col(i, 1/factor)
    H = Sequence([], f.parent().change_ring(QQ))
    for h in filter(None, B*monomials):
        H.append(h)
        I = H.ideal()
        if I.dimension() == -1:
            H.pop()
        elif I.dimension() == 0:
            roots = []
            for root in I.variety(ring=ZZ):
                root = tuple(R(root[var]) for var in f.variables())
                roots.append(root)
            return roots
    return []

# Step 1: Find k and l using bivariate Coppersmith
print("\n[*] Step 1: Finding k and l...")
PR.<x, y> = PolynomialRing(Zmod(e * MOD), 2)
A = e*(dp_low + dq_low) - e^2 * dp_low * dq_low - 1
f = (N-1)*x*y - (e*dq_low-1)*x - (e*dp_low-1)*y + A

roots = defund_multivariate(f, bounds=(e, e), m=3, d=4)
k, l = int(roots[0][0]), int(roots[0][1])
print(f"[+] k = {k}")
print(f"[+] l = {l}")

# Step 2: Use Coppersmith to find h_dp (high bits of dp)
# From e*dp = k*(p-1) + 1:
# e*(h_dp * 2^512 + dp_low) + k - 1 ≡ 0 (mod k*p)
# This polynomial has small root h_dp mod k*p, and k*p | k*N

print("\n[*] Step 2: Finding h_dp using Coppersmith...")

p = None
for k_val in [k, l]:
    print(f"    Trying k = {k_val}...")
    
    if k_val % 2 == 0:
        print(f"    k is even, checking if inverse exists...")
    
    try:
        # Polynomial: f(x) = e*(x*2^512 + dp_low) + k - 1
        # This has root h_dp mod k*p
        # We work mod k*N
        
        PR.<x> = PolynomialRing(Zmod(k_val * N))
        f = e * (x * MOD + dp_low) + k_val - 1
        
        # h_dp is about 512 bits
        # beta = log(k*p) / log(k*N) ≈ log(k) + log(p) / log(k) + log(N)
        # ≈ (16 + 1024) / (16 + 2048) ≈ 0.5
        
        print(f"        Trying sage small_roots...")
        for beta in [0.5, 0.49, 0.48, 0.45, 0.4, 0.35]:
            for eps in [0.01, 0.02, 0.03, 0.04, 0.05]:
                try:
                    roots = f.monic().small_roots(X=2^512, beta=beta, epsilon=eps)
                    if roots:
                        print(f"        Found {len(roots)} roots with beta={beta}, eps={eps}")
                        for h_dp in roots:
                            h_dp = int(h_dp)
                            print(f"            h_dp = {h_dp} ({h_dp.bit_length()} bits)")
                            if h_dp <= 0:
                                continue
                            dp_full = h_dp * MOD + dp_low
                            kp = e * dp_full + k_val - 1
                            p_cand = gcd(int(kp), N)
                            if 1 < p_cand < N and N % p_cand == 0:
                                p = int(p_cand)
                                print(f"        [+] SUCCESS!")
                                break
                        if p:
                            break
                except Exception as ex:
                    continue
            if p:
                break
        if p:
            break
            
    except Exception as ex:
        print(f"    Error: {ex}")
        continue

# If sage's small_roots failed, try the custom lattice approach from the paper
if p is None:
    print("\n[*] Sage small_roots failed, trying custom lattice...")
    
    def solve_custom_lattice(k_val, m, t):
        """Custom lattice from paper's author"""
        try:
            inv_e2i = pow(int(e * MOD), -1, int(k_val * N))
        except:
            return []
        
        a = (e * dp_low + k_val - 1) * inv_e2i % (k_val * N)
        
        R.<x> = QQ[]
        f = x + a
        X = 2^512
        
        F = []
        S = []
        for j in range(m+1):
            h = f^j * Integer(k_val)^(m-j) * Integer(N)^(max(0, t-j))
            F.append(h)
            S.append(x^j)
        
        dim = len(F)
        MAT = Matrix(ZZ, dim, dim)
        for i in range(dim):
            poly = F[i](x * X)
            coeffs = poly.coefficients(sparse=False)
            for j in range(min(len(coeffs), dim)):
                MAT[i, j] = Integer(coeffs[j])
        
        MAT = MAT.LLL()
        
        results = []
        for row in range(dim):
            h = sum(Integer(MAT[row, i]) * x^i // X^i for i in range(dim))
            try:
                roots = h.roots(ring=ZZ)
                for r, _ in roots:
                    results.append(int(r))
            except:
                pass
        return results
    
    for k_val in [k, l]:
        if gcd(e * MOD, k_val * N) != 1:
            continue
        print(f"    Trying k = {k_val} with custom lattice...")
        for m_val in [20, 25, 30]:
            t_val = m_val // 2
            print(f"        m={m_val}, t={t_val}...", end=" ")
            roots = solve_custom_lattice(k_val, m_val, t_val)
            print(f"found {len(roots)} roots")
            for h_dp in roots:
                if h_dp <= 0:
                    continue
                dp_full = abs(h_dp) * MOD + dp_low
                kp = e * dp_full + k_val - 1
                p_cand = gcd(int(kp), N)
                if 1 < p_cand < N:
                    p = int(p_cand)
                    print(f"        [+] SUCCESS!")
                    break
            if p:
                break
        if p:
            break

if p is None:
    print("[-] Failed to find p")
    exit(1)

q = N // p
print(f"\n[+] p = {p}")
print(f"[+] q = {q}")

# Verify
assert p * q == N
assert is_prime(p) and is_prime(q)

# Step 3: Decrypt
print("\n[*] Step 3: Decrypting...")
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m = pow(c, d, N)
flag = long_to_bytes(int(m))

print(f"\n[+] Raw bytes: {flag}")
try:
    print(f"[+] FLAG: {flag.decode()}")
except:
    print("[!] UTF-8 decode failed, trying with different k...")
    # The issue is we might have used the wrong k - dp corresponds to p, dq to q
    # If we used k (for dp) but got wrong result, try swapping
    print("[*] Trying to decrypt using dq_low with l instead...")
    
    # Try the other approach - use dq_low with l to get q
    l_val = l if k_val == k else k
    if l_val % 2 != 0:
        l_inv = pow(l_val, -1, MOD)
        q_low = (e * dq_low + l_val - 1) * l_inv % MOD
        
        PR3.<z> = PolynomialRing(Zmod(N))
        f_q = z * MOD + q_low
        
        for beta in [0.5, 0.499, 0.49]:
            for eps in [0.01, 0.02, 0.03]:
                try:
                    roots = f_q.monic().small_roots(X=2^512, beta=beta, epsilon=eps)
                    for r in roots:
                        q_high = int(r)
                        q_cand = q_high * MOD + q_low
                        if q_cand > 1 and N % q_cand == 0:
                            q = int(q_cand)
                            p = N // q
                            phi = (p-1)*(q-1)
                            d = pow(e, -1, phi)
                            m = pow(c, d, N)
                            flag = long_to_bytes(int(m))
                            print(f"[+] Raw bytes: {flag}")
                            print(f"[+] FLAG: {flag.decode()}")
                            exit(0)
                except:
                    continue
