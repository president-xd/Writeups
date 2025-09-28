#!/usr/bin/env python3
import socket, json, time, re, math, sys

HOST = "chal.sunshinectf.games"
PORT = 25201

POP = 100
DIM = 10
TARGET = 0.95

READ_CHUNK = 8192

def recv_blob(sock, wait=0.25):
    sock.setblocking(False)
    buf = b""
    end = time.time() + wait
    while time.time() < end:
        try:
            chunk = sock.recv(READ_CHUNK)
            if not chunk:
                break
            buf += chunk
            end = time.time() + 0.12
        except BlockingIOError:
            time.sleep(0.02)
    sock.setblocking(True)
    return buf.decode(errors="ignore")

def parse_report(txt):
    # grab the last JSON object with "scores"
    objs = re.findall(r"\{.*?\}", txt, flags=re.DOTALL)
    for s in reversed(objs):
        try:
            d = json.loads(s)
            if isinstance(d.get("scores"), list):
                return d
        except Exception:
            continue
    return None

def clamp01(x): 
    return 0.0 if x < 0.0 else (1.0 if x > 1.0 else x)

def bracket_points(lo, hi, k=10):
    # 10 evenly spaced points, inclusive
    if hi <= lo: 
        return [clamp01(lo)]*k
    step = (hi - lo) / (k - 1)
    return [clamp01(lo + i*step) for i in range(k)]

def shrink_around(lo, hi, x, factor=0.35):
    # shrink [lo,hi] around x, keeping inside [0,1]
    span = (hi - lo) * factor
    new_lo = clamp01(x - span/2)
    new_hi = clamp01(x + span/2)
    # ensure non-degenerate
    if new_hi - new_lo < 1e-6:
        new_lo = clamp01(max(0.0, x - 1e-3))
        new_hi = clamp01(min(1.0, x + 1e-3))
    return new_lo, new_hi

def build_generation_vectors(best_vec, brackets):
    """
    We allocate 10 samples per gene (10 genes * 10 = 100).
    For gene i, we sweep 10 values across its current bracket while other
    genes stay at their current best.
    Return: samples list (length 100) AND an index map telling us which
    gene/value each sample corresponds to.
    """
    samples = []
    idxmap = []  # (gene_index, value)
    for i in range(DIM):
        vals = bracket_points(brackets[i][0], brackets[i][1], 10)
        for v in vals:
            x = best_vec[:]
            x[i] = v
            samples.append(x)
            idxmap.append((i, v))
    assert len(samples) == POP
    return samples, idxmap

def main():
    # per-gene brackets and best guess
    brackets = [(0.0, 1.0) for _ in range(DIM)]
    best_vec = [0.5]*DIM
    best_score = -1.0
    best_any_vec = None

    with socket.create_connection((HOST, PORT), timeout=10) as s:
        # banner
        sys.stdout.write(recv_blob(s))
        sys.stdout.flush()

        for gen in range(1, 101):
            # If we already hit ≥ TARGET, flood with that genome to force average ≥ 95
            if best_score >= TARGET and best_any_vec is not None:
                pop = [best_any_vec[:] for _ in range(POP)]
            else:
                pop, idxmap = build_generation_vectors(best_vec, brackets)

            s.sendall((json.dumps({"samples": pop}) + "\n").encode())
            resp = recv_blob(s)
            if resp:
                sys.stdout.write(resp)
                sys.stdout.flush()

            low = resp.lower()
            if "flag" in low or "sunshine{" in low or "congrat" in low or "success" in low:
                break

            report = parse_report(resp)
            if not report:
                continue

            scores = report["scores"]
            # Track overall best
            local_best_idx = max(range(len(scores)), key=lambda i: scores[i])
            if scores[local_best_idx] > best_score:
                best_score = scores[local_best_idx]
                best_any_vec = pop[local_best_idx][:]
            # If we just discovered ≥95%, next loop will submit 100 clones.
            if best_score >= TARGET:
                # print a short hint so user sees we’re switching modes
                print(f"\n[+] Found genome ≥ {TARGET:.2%} — cloning it next generation...\n")
                continue

            # Use the structured sweep to update per-gene brackets and best_vec
            # We sent 10 blocks, each of 10 samples (one per value) for gene i.
            for gi in range(DIM):
                block_start = gi * 10
                block_end = block_start + 10
                block_scores = scores[block_start:block_end]
                block_vals = [pop[k][gi] for k in range(block_start, block_end)]
                j = max(range(10), key=lambda t: block_scores[t])
                argmax_v = block_vals[j]
                # Update bracket for gene gi
                lo, hi = brackets[gi]
                brackets[gi] = shrink_around(lo, hi, argmax_v, factor=0.35)
                # Update best_vec coordinate to the best tested value
                best_vec[gi] = argmax_v

        # drain any final flag text
        tail = recv_blob(s, wait=0.5)
        if tail:
            sys.stdout.write(tail)
            sys.stdout.flush()

if __name__ == "__main__":
    main()
