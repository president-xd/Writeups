from Crypto.Util.number import long_to_bytes
import sys
import time

# Challenge data
c = 14617737701245701051442576201966895913281170269511419933129407961403772828494960013627619629982620524933905900649014563540301722475717908474769022912370226196157520720821869072349341135297822347569260420263782354504214809753828254491088635941603753647218107777872955055564609704547564183681103521853293408909
e = 65537
N = 65865845518340233803656024321921242543203714938746940112806745010868374771199773112691994058854618281224438683338564616804438291432406897439388013721476413881476763817461921988354548803122412973120109349749870042062513737474710258672501569257755507682768501763957229397529887433613060327675823734298300499769

leaky = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0]

# Sanity checks
assert len(leaky) == 493, f"leaky array length is {len(leaky)}, expected 493"
assert all(b == 0 for b in leaky[0:19]), "bits 0-18 should be zeroed"
assert all(b == 0 for b in leaky[120:139]), "bits 120-138 should be zeroed"
print(f"leaky array length: {len(leaky)} OK")
print(f"Zero regions verified OK")

# Reconstruct known portion of p from leaked bits (LSB-first order)
p_known = sum(b * 2^i for i, b in enumerate(leaky))
# Bit 511 is always 1 for a 512-bit prime (p >= 2^511)
p_known += 2^511

print(f"log2(N) = {RR(log(N, 2)):.2f}")
print(f"N^0.49 = 2^{RR(0.49*log(N,2)):.2f}, must be < 2^511 for beta=0.49 to be valid")

# Unknown bit regions:
#   bits 0-18   (19 bits) -> x_low
#   bits 120-138 (19 bits) -> x_mid
#   bits 493-510 (18 bits) -> brute-forced (bit 511 already set)
#
# After brute-forcing the top 18 bits, the remaining unknown is:
#   x = x_low + x_mid * 2^120
# where x_low < 2^19 and x_mid < 2^19, so x < 2^140.
#
# Key fix: beta=0.49 (not 0.5!) because p might be < sqrt(N).
# Since p >= 2^511 > N^0.49, the bound is satisfied.
# With beta=0.49, epsilon=0.09: X < N^(0.2401 - 0.09) = N^0.1501 ≈ 2^153 > 2^140 ✓

PR.<x> = PolynomialRing(Zmod(N))
step = 2^493
bound = 2^140
total = 2^18

print(f"Brute-forcing {total} candidates for bits 493-510...")
print(f"Using beta=0.49, epsilon=0.09")
sys.stdout.flush()

t0 = time.time()

for high in range(total):
    p_partial = p_known + high * step

    f = (x + p_partial).monic()
    roots = f.small_roots(X=bound, beta=0.49, epsilon=0.09)

    if roots:
        for r in roots:
            p_cand = int(p_partial + int(r))
            if p_cand > 1 and N % p_cand == 0:
                q = N // p_cand
                phi = (p_cand - 1) * (q - 1)
                d = pow(e, -1, int(phi))
                m = pow(c, d, N)
                flag = long_to_bytes(m)
                print(f"\nFound p = {p_cand}")
                print(f"Found q = {q}")
                print(f"Flag: {flag}")
                print(f"Time: {time.time()-t0:.1f}s")
                sys.exit(0)

    if high % 5000 == 0:
        elapsed = time.time() - t0
        rate = high / elapsed if elapsed > 0 else 0
        eta = (total - high) / rate if rate > 0 else 0
        print(f"  Progress: {high}/{total} ({elapsed:.1f}s, ~{eta:.0f}s remaining)")
        sys.stdout.flush()

print("No solution found.")
