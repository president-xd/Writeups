#!/usr/bin/env python3
import argparse, binascii, sys
from collections import defaultdict
from pwn import remote
from ortools.sat.python import cp_model

def hexline_to_bytes(line: bytes) -> bytes:
    s = line.strip()
    try:
        return bytes.fromhex(s.decode())
    except Exception:
        return None

def collect_ciphertexts(host, port, count, send=b"x", greet_expect=True):
    io = remote(host, port)
    cts = []
    if greet_expect:
        try:
            banner = io.recvline(timeout=5)
            # print(f"[+] Banner: {banner.decode(errors='ignore').strip()}")
        except EOFError:
            pass
    for i in range(count):
        io.sendline(send)
        line = io.recvline(timeout=10)
        ct = hexline_to_bytes(line)
        if ct is None:
            # Sometimes the server may print a stray line; try once more
            line2 = io.recvline(timeout=10)
            ct = hexline_to_bytes(line2)
        if ct is None:
            io.close()
            raise RuntimeError(f"Non-hex response at sample {i}: {line!r}")
        cts.append(ct)
    # Try to exit cleanly
    try:
        io.sendline(b"exit")
    except Exception:
        pass
    io.close()
    n = len(cts[0])
    if any(len(c) != n for c in cts):
        raise RuntimeError("Ciphertexts have inconsistent lengths")
    return cts

def domain_from_string(s):
    return [b for b in s.encode("latin1")]

def solve_flag(ciphertexts, alphabet=None, prefix=b"", suffix=b""):
    """
    Solve for FLAG bytes F[0..n-1] s.t. for each sample t,
    K_t[i] = C_t[i] XOR F[i] are all pairwise distinct.
    """
    n = len(ciphertexts[0])
    T = len(ciphertexts)
    # Default alphabet: printable ASCII 0x20..0x7E
    if alphabet is None:
        alphabet = list(range(0x20, 0x7F))

    # Apply prefix/suffix constraints by position
    fixed = {}
    for i, ch in enumerate(prefix):
        fixed[i] = ch
    for j, ch in enumerate(suffix[::-1]):
        fixed[n - 1 - j] = ch

    model = cp_model.CpModel()

    # Create variables for flag bytes
    # Where fixed, lock them; else restrict to alphabet
    F = []
    for i in range(n):
        if i in fixed:
            v = model.NewIntVar(fixed[i], fixed[i], f"F_{i}")
        else:
            v = model.NewIntVarFromDomain(
                cp_model.Domain.FromValues(alphabet), f"F_{i}"
            )
        F.append(v)

    # For each sample t, create K_t[i] and link via a small table constraint:
    # (F[i], K_t[i]) allowed pairs are {(x, x ^ C_t[i]) | x in domain(F[i])}
    K = []
    for t, C in enumerate(ciphertexts):
        Kt = []
        for i in range(n):
            k = model.NewIntVar(0, 255, f"K_{t}_{i}")
            # Build allowed pairs for (F[i], k)
            # We must reflect exactly the current domain of F[i].
            # If F[i] is fixed, this is a single pair.
            if F[i].Proto().domain and len(F[i].Proto().domain) == 2 and F[i].Proto().domain[0] == F[i].Proto().domain[1]:
                xvals = [F[i].Proto().domain[0]]
            else:
                xvals = alphabet
            tuples = [(x, x ^ C[i]) for x in xvals]
            model.AddAllowedAssignments([F[i], k], tuples)
            Kt.append(k)
        # AllDifferent for each output t
        model.AddAllDifferent(Kt)
        K.append(Kt)

    # Optional: encourage readable flags (not necessary but can speed search)
    # e.g., force first char to be letter/digit if not fixed
    if 0 not in fixed:
        first_is_printable = model.NewBoolVar("first_is_printable")
        model.AddLinearConstraint(F[0], 48, 122)  # '0'..'z'

    solver = cp_model.CpSolver()
    solver.parameters.max_time_in_seconds = 60.0  # adjust as needed
    solver.parameters.num_search_workers = 8

    status = solver.Solve(model)
    if status not in (cp_model.OPTIMAL, cp_model.FEASIBLE):
        return None

    flag = bytes([solver.Value(F[i]) for i in range(n)])
    # sanity: verify constraints
    for t, C in enumerate(ciphertexts):
        Ks = [ (C[i] ^ flag[i]) for i in range(n) ]
        if len(set(Ks)) != n:
            raise AssertionError("Solution violates AllDifferent (unexpected)")
    return flag

def main():
    ap = argparse.ArgumentParser(description="Recover flag via AllDifferent constraints")
    ap.add_argument("--host", default="ctfi.ng")
    ap.add_argument("--port", type=int, default=31556)
    ap.add_argument("-N", "--num", type=int, default=100, help="number of samples")
    ap.add_argument("--send", default="x", help="string to send each time")
    ap.add_argument("--prefix", default="", help="known prefix, e.g. CTF{")
    ap.add_argument("--suffix", default="", help="known suffix, e.g. }")
    ap.add_argument("--alphabet", default="printable",
                    help="either 'printable' or a literal string of allowed chars")
    args = ap.parse_args()

    if args.alphabet == "printable":
        alphabet = list(range(0x20, 0x7F))
    else:
        alphabet = domain_from_string(args.alphabet)

    cts = collect_ciphertexts(args.host, args.port, args.num, args.send.encode())
    print(f"[+] Collected {len(cts)} samples of length {len(cts[0])}")

    flag = solve_flag(cts, alphabet=alphabet,
                      prefix=args.prefix.encode(),
                      suffix=args.suffix.encode())
    if flag is None:
        print("[-] No solution found. Try increasing samples (-N), tightening alphabet, or adding a prefix/suffix hint.")
        sys.exit(2)
    print(f"[+] FLAG: {flag}")

# Usage:
# python3 solve_all_diff.py \
#  --host ctfi.ng --port 31556 \
#  -N 150 \
#  --send "x" \
#  --prefix "CTF{" --suffix "}"

if __name__ == "__main__":
    main()
