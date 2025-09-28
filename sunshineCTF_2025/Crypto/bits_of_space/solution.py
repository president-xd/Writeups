#!/usr/bin/env python3
import os, sys, socket, struct

HOST = "sunshinectf.games"
PORT = 25401
BLOB = "voyager.bin"

DEVICES = [
    0x13371337,  # Status Relay
    0x1337babe,  # Ground Station Alpha
    0xdeadbeef,  # Lunar Relay
]

def recv_all(sock, timeout=6.0) -> bytes:
    sock.settimeout(timeout)
    data = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except Exception:
        pass
    return data

def talk(payload: bytes) -> bytes:
    with socket.create_connection((HOST, PORT), timeout=8) as s:
        try:
            hello = s.recv(4096)  # banner + prompt
            if hello:
                sys.stdout.write(hello.decode("utf-8", "replace"))
        except Exception:
            pass
        s.sendall(payload)
        # don't shutdown write; just read until the server closes
        return recv_all(s, timeout=6.0)

def flip_iv_to_target(iv: bytes, orig_id: int, target_id: int) -> bytes:
    ivb = bytearray(iv)
    have = struct.pack("<I", orig_id)
    want = struct.pack("<I", target_id)
    for i in range(4):
        ivb[i] ^= have[i] ^ want[i]
    return bytes(ivb)

def main():
    if not os.path.exists(BLOB):
        print(f"[!] {BLOB} not found.")
        sys.exit(1)
    blob = open(BLOB, "rb").read()
    if len(blob) != 48:
        print(f"[!] {BLOB} must be exactly 48 bytes (IV(16)|C1(16)|C2(16)); got {len(blob)}.")
        sys.exit(1)

    iv, c1, c2 = blob[:16], blob[16:32], blob[32:48]

    print("[*] Probing the provided blob on the live host…")
    base = talk(blob)
    out = base.decode("utf-8", "replace")
    sys.stdout.write(out)

    if "You have reached the restricted relay" in out:
        # already lucky; flag printed
        sys.exit(0)

    if "Authenticated device:" not in out and "Invalid subscription" in out:
        print("\n[!] The sample ciphertext is NOT valid for this host’s key.")
        print("[!] With only relay.py and this invalid blob, you cannot recover the flag.\n"
              "    (You’d need a live-valid 48-byte ciphertext or the server’s AES key.)")
        sys.exit(2)

    print("[*] Trying IV flips to force device_id -> 0xdeadbabe…")
    for guess in DEVICES:
        forged_iv = flip_iv_to_target(iv, guess, 0xdeadbabe)
        forged = forged_iv + c1 + c2
        resp = talk(forged).decode("utf-8", "replace")
        sys.stdout.write(resp)
        if "You have reached the restricted relay" in resp:
            print("[*] Success — restricted relay reached.")
            # flag already printed by server
            return

    print("\n[!] None of the IV flips worked.")
    print("[!] That means your blob is either invalid for this host’s key, "
          "or it wasn’t originally one of the three public device IDs.")
    print("[!] Without a live-valid blob or the AES key, this challenge cannot be solved further from the client side.")

if __name__ == "__main__":
    main()
