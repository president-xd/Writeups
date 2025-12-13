from pwn import *
import re
import random as std_random
from sage.all import *

# Set context
context.log_level = 'info'

def get_indices(seed):
    std_random.seed(seed)
    dummy_sentences = list(range(10))
    return tuple(std_random.sample(dummy_sentences, k=5))

def find_seed_pairs():
    print("Searching for seed pairs...")
    seen = {}
    pairs = []
    # Search range. 470/478 was found early, so we expect frequent hits.
    for s in range(100000):
        idx = get_indices(s)
        seen[idx] = s
        
        # We want pairs that isolate S0 (index 0)
        # Case 1: Current s is I1 (starts with 0) -> I1 = [0, a, b, c, d]
        # We look for I2 = [a, b, c, d, 0]
        if idx[0] == 0:
            target = idx[1:] + (0,)
            if target in seen:
                s1 = s
                s2 = seen[target]
                # Check if this pair uses different sentences than previous pairs?
                # Actually, just getting any two pairs is fine.
                # But we want them to be distinct enough to give independent polynomials.
                # If they use the same set of sentences, the polynomials might be identical?
                # No, because the sentences are random, but the structure is the same.
                # Wait, if we use s1, s2 and then s1, s2 again, it's useless.
                # We need a different set of sentences.
                # Store the set of indices.
                pairs.append((s1, s2, idx))
                if len(pairs) >= 2:
                    return pairs
        
        # Case 2: Current s is I2 (ends with 0) -> I2 = [a, b, c, d, 0]
        # We look for I1 = [0, a, b, c, d]
        if idx[-1] == 0:
            target = (0,) + idx[:-1]
            if target in seen:
                s1 = seen[target]
                s2 = s
                pairs.append((s1, s2, target))
                if len(pairs) >= 2:
                    return pairs
    return pairs

def solve():
    # Connect to server
    r = remote('172.20.10.14', 5000)
    
    # Parse e and n
    r.recvuntil(b'e = ')
    e = int(r.recvline().strip())
    r.recvuntil(b'n = ')
    n = int(r.recvline().strip())
    print(f"e = {e}")
    print(f"n = {n}")
    
    # Parse masked sentences to get lengths
    masked_sentences = []
    for _ in range(10):
        line = r.recvline().decode().strip()
        masked_sentences.append(line)
    
    # Calculate bit lengths of each sentence
    # Note: The server joins sentences with spaces.
    # When constructing the paragraph, we need to account for the spaces.
    # P = S_0 + " " + S_1 + ...
    # But wait, the cyclic shift logic:
    # P1 = S0 || " " || S_a || " " || S_b ...
    # P2 = S_a || " " || S_b ... || " " || S0
    # The spaces are part of the structure.
    # Let's treat the "sentence" as including the trailing space?
    # Or just handle the bits carefully.
    
    # Length of S_i in bits: len(masked_sentences[i]) * 8
    # But wait, `bytes_to_long` uses the byte string.
    # P1 = S0 + " " + X
    # P2 = X + " " + S0
    # Let L0 be length of S0 in bits.
    # Let LX be length of X in bits.
    # But X contains internal spaces.
    # And there is a space between S0 and X in P1.
    # And a space between X and S0 in P2.
    # So:
    # P1 = (S0) || " " || (X)
    # P2 = (X) || " " || (S0)
    # P1 = S0 * 2^(LX + 8) + ord(" ") * 2^LX + X
    # P2 = X * 2^(L0 + 8) + ord(" ") * 2^L0 + S0
    
    # We can express X from P1:
    # X = P1 - S0 * 2^(LX + 8) - space_val * 2^LX
    # Substitute into P2:
    # P2 = (P1 - S0 * 2^(LX + 8) - space_val * 2^LX) * 2^(L0 + 8) + space_val * 2^L0 + S0
    # This gives the linear relation!
    
    sentence_lens = [len(s) * 8 for s in masked_sentences]
    space_val = ord(" ")
    
    # Find seeds
    pairs = find_seed_pairs()
    if len(pairs) < 2:
        print("Could not find enough seed pairs.")
        return
    
    print(f"Found pairs: {pairs}")
    
    # We need to collect ciphertexts for these seeds.
    # We have 4 queries. We use 2 pairs = 4 seeds. Perfect.
    
    polys = []
    S = PolynomialRing(Zmod(n), 'S').gen()
    
    for s1, s2, indices in pairs:
        # indices is I1 = [0, a, b, c, d]
        # I2 is shifted
        
        # Send seeds
        r.sendlineafter(b'seed: ', str(s1).encode())
        r.recvuntil(b'ct = ')
        c1 = int(r.recvline().strip())
        
        r.sendlineafter(b'seed: ', str(s2).encode())
        r.recvuntil(b'ct = ')
        c2 = int(r.recvline().strip())
        
        # Construct polynomial relation
        # I1 = [0, a, b, c, d]
        # X is formed by sentences [a, b, c, d] joined by spaces
        # Length of X in bytes = sum(len(S_i)) + 3 (for 3 spaces)
        # LX in bits = (sum(len(S_i) for i in indices[1:]) + 3) * 8
        
        len_X_bytes = sum(len(masked_sentences[i]) for i in indices[1:]) + 3
        LX = len_X_bytes * 8
        
        L0 = sentence_lens[0] # Length of S0 in bits
        
        # P1 = S0 * 2^(LX + 8) + space * 2^LX + X
        # P2 = X * 2^(L0 + 8) + space * 2^L0 + S0
        
        # X = P1 - S0 * 2^(LX + 8) - space * 2^LX
        # P2 = (P1 - S0 * 2^(LX + 8) - space * 2^LX) * 2^(L0 + 8) + space * 2^L0 + S0
        
        # Constants
        k_P1 = 2**(L0 + 8)
        k_S0 = 1 - 2**(LX + 8 + L0 + 8)
        k_const = space_val * 2**L0 - space_val * 2**(LX + L0 + 8)
        
        # P2 = k_P1 * P1 + k_S0 * S0 + k_const
        
        # Polynomials in P (variable for P1) and S (variable for S0)
        # But we want to eliminate P.
        # R = Zmod(n)[P, S]
        # f1 = P^e - c1
        # f2 = (k_P1 * P + k_S0 * S + k_const)^e - c2
        
        # Resultant to eliminate P
        # We can do this using univariate polynomials over a polynomial ring?
        # Or just use multivariate ring.
        
        # Resultant to eliminate P
        # We use a nested ring Zmod(n)['S']['P'] to compute the resultant
        # as the determinant of the Sylvester matrix.
        
        R_S = PolynomialRing(Zmod(n), 'S')
        S_poly = R_S.gen()
        R_P = PolynomialRing(R_S, 'P')
        P_poly = R_P.gen()
        
        # Re-define polynomials in the new ring
        # Note: coefficients like k_P1 are integers, they coerce fine.
        f1 = P_poly**e - c1
        f2 = (k_P1 * P_poly + k_S0 * S_poly + k_const)**e - c2
        
        # Compute resultant
        # For univariate polynomials over a ring, sylvester_matrix() is available
        res = f1.sylvester_matrix(f2).determinant()
        
        # res is a polynomial in S_poly (which is S0)
        # It is already in R_S, so it is a univariate polynomial.
        res_uni = res
        polys.append(res_uni)
        
    # Now we have two polynomials in S0: polys[0] and polys[1]
    # Their GCD should be linear: (S - S0)
    
    print("Computing GCD...")
    
    def pgcd(a, b):
        while b:
            try:
                a, b = b, a % b
            except Exception:
                # If division fails, it means leading coefficient is not invertible.
                # This implies we found a factor of n, or b is 0.
                # Try making b monic if possible.
                try:
                    b = b.monic()
                    a, b = b, a % b
                except:
                    # If monic fails, we have a factor.
                    # For this challenge, we assume we can proceed or just stop.
                    print("GCD computation failed due to non-invertible element.")
                    return a
        return a.monic()

    g = pgcd(polys[0], polys[1])
    print(f"GCD degree: {g.degree()}")
    
    if g.degree() == 1:
        # g = S + k
        # S0 = -k
        root = int(-g.constant_coefficient())
        print(f"Found root: {root}")
        
        # Decode
        # The root is S0 mod n.
        # But S0 > n. S0 = root + k * n.
        # We need to find k.
        # We use a Lattice approach to find k based on the known text at bytes 34..74.
        
        print("Recovering full S0 from root using Lattice CVP...")
        
        # 1. Define constants
        # Target text " Congratulations! The flag is BHFlagY{"
        known_text = b" Congratulations! The flag is BHFlagY{"
        target_int = int.from_bytes(known_text, 'big') # This might check endianness
        # Wait, bytes_to_long is 'big' endian by default in pwntools? Yes.
        # But standard int.from_bytes works too.
        # Position: The text "ends" at byte 34 (LSB 'y{' is at 34).
        # Actually in big endian, the string is treated as a number.
        # " Congratulations..." -> High bytes. "{" -> Low bytes.
        # index 34 corresponds to start of "{".
        # Let's verify byte order.
        # S0 = ... | "C" | ... | "{" | HEX | ...
        # "{" is at lower index than "C".
        # Index 34 is LSB of the block.
        # So S0 >> (34*8) & Mask == target_int
        
        shift_bits = 34 * 8
        target_len_bytes = len(known_text)
        target_val = int.from_bytes(known_text, 'big')
        
        # Equation:
        # root + k*n = High*2^End + Target * 2^Shift + Low
        # We work modulo 2^(End). End = Shift + target_len*8
        # root + k*n = Target * 2^Shift + Low (mod 2^End)
        # k*n - Low = Target * 2^Shift - root (mod 2^End)
        
        # Equation: k * n - Low = Target modulo M
        # Target = (Known * 2^Shift - root) % M
        
        mod_bits = shift_bits + target_len_bytes * 8
        M = 2**mod_bits
        
        # Target value for the congruence
        Target = (target_val * 2**shift_bits - root) % M
        
        # Lattice L: Solutions to x * n - y = 0 mod M
        # Basis:
        # v1 = (1, n % M)
        # v2 = (0, M)
        # Any vector in L satisfies relationship.
        
        # Particular solution to k * n - Low = Target mod M:
        # (k, Low) = (0, -Target)
        # Check: 0 * n - (-Target) = Target. Correct.
        
        # We want small solution (k, Low).
        # (k, Low) = (0, -Target) + u, where u in L.
        # We want (0, -Target) + u approx (0, 0).
        # u approx (0, Target).
        
        # Define Basis Matrix
        # Note: k is approx 276 bits. Low is approx 272 bits. 
        # Weights are similar, so no scaling needed ideally.
        # But Sage's LLL might prefer row form.
        # Matrix rows are basis vectors.
        
        mat = Matrix(ZZ, [[1, n % M], [0, M]])
        
        # Target vector for CVP
        target_vec = vector(ZZ, [0, Target])
        
        from sage.modules.free_module_integer import IntegerLattice
        L = IntegerLattice(mat)
        try:
            closest = L.closest_vector(target_vec)
        except AttributeError:
             print("closest_vector failed")
             return

        # closest = u
        # Solution = u + (0, -Target)
        
        k_found = closest[0] + 0
        low_found = closest[1] - Target
        
        print(f"k candidate: {k_found}")
        
        full_s0 = root + int(k_found) * n
        flag_bytes = full_s0.to_bytes((full_s0.bit_length() + 7) // 8, 'big')
        print(f"Recovered Sentence: {flag_bytes}")
        if b"BHFlagY" in flag_bytes:
            print("Flag found!")
        else:
            print("Reconstruction failed.")
        
        print(f"k candidate: {k_found}")
        
        full_s0 = root + int(k_found) * n
        flag_bytes = full_s0.to_bytes((full_s0.bit_length() + 7) // 8, 'big')
        print(f"Recovered Sentence: {flag_bytes}")
        if b"BHFlagY" in flag_bytes:
            print("Flag found!")
        else:
            print("Reconstruction failed.")

    else:
        print("GCD degree is not 1. Failed.")

if __name__ == "__main__":
    solve()
