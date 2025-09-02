#!/usr/bin/env python3
import re
import socket
import sys

HOST = "c1.arena.airoverflow.com"
PORT = 24516
TIMEOUT = 10

# The plaintext of a_quote_from_a_leader.txt (83 bytes)
QUOTE = (
    b"I do not believe in taking the right decision, I take a decision and make it right."
)

def recv_all_until(sock, needles, timeout=TIMEOUT):
    sock.settimeout(timeout)
    buf = b""
    found = {n: False for n in needles}
    while not all(found.values()):
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        for n in needles:
            if (not found[n]) and (n in buf.decode(errors="ignore")):
                found[n] = True
    return buf

def parse_hex_pair(data: str):
    """
    Extract the two hex strings printed like:
      Encrypted Data: <hex>
      Encrypted Flag: <hex>
    """
    # tolerant to extra whitespace or banners
    m1 = re.search(r"Encrypted Data:\s*([0-9a-fA-F]+)", data)
    m2 = re.search(r"Encrypted Flag:\s*([0-9a-fA-F]+)", data)
    if not (m1 and m2):
        raise ValueError("Could not find both hex blobs in server output.")
    return bytes.fromhex(m1.group(1)), bytes.fromhex(m2.group(1))

def recover_flag(c_data: bytes, c_flag: bytes) -> str:
    if len(QUOTE) != len(c_data):
        raise ValueError(f"Quote length ({len(QUOTE)}) != Encrypted Data length ({len(c_data)})")

    # CTR keystream reuse:
    # K = C_data ⊕ P_data
    keystream_prefix = bytes(cd ^ pd for cd, pd in zip(c_data[:len(c_flag)], QUOTE[:len(c_flag)]))
    # P_flag = C_flag ⊕ K
    p_flag = bytes(cf ^ ks for cf, ks in zip(c_flag, keystream_prefix))

    flag = p_flag.decode("utf-8", errors="strict")
    if not (flag.startswith("ARENA{") and flag.endswith("}")):
        # Still print it for debugging, but warn
        raise ValueError(f"Recovered flag looks suspicious: {flag!r}")
    return flag

def main():
    try:
        with socket.create_connection((HOST, PORT), timeout=TIMEOUT) as s:
            data = recv_all_until(s, needles=["Encrypted Data:", "Encrypted Flag:"]).decode(errors="ignore")
    except Exception as e:
        print(f"[!] Network error: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        c_data, c_flag = parse_hex_pair(data)
    except Exception as e:
        print(f"[!] Parse error: {e}", file=sys.stderr)
        print("----- server output -----")
        print(data)
        print("-------------------------")
        sys.exit(1)

    try:
        flag = recover_flag(c_data, c_flag)
    except Exception as e:
        print(f"[!] Recovery error: {e}", file=sys.stderr)
        sys.exit(1)

    print(flag)

if __name__ == "__main__":
    main()
