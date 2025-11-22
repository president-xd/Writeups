#!/usr/bin/env python3
import socket
import sys
import json
import math
from functools import reduce

from Crypto.Util.number import long_to_bytes


E = 5  # public exponent used by the challenge


def iroot(k, n):
    """
    Integer k-th root via binary search.
    Returns (root, exact) where exact is True if root**k == n.
    """
    if n < 0:
        raise ValueError("n must be non-negative")
    if n == 0:
        return 0, True

    # Find an upper bound
    high = 1
    while high ** k <= n:
        high <<= 1
    low = high >> 1

    # Binary search between low and high
    while low < high:
        mid = (low + high) // 2
        mid_k = mid ** k
        if mid_k == n:
            return mid, True
        if mid_k < n:
            low = mid + 1
        else:
            high = mid

    root = low
    if root ** k > n:
        root -= 1
    return root, (root ** k == n)


def crt(remainders, moduli):
    """
    Chinese Remainder Theorem: solves x = r_i (mod n_i) for all i.
    Returns x modulo N = prod(n_i).
    """
    assert len(remainders) == len(moduli)
    N = reduce(lambda a, b: a * b, moduli, 1)
    x = 0
    for r, n in zip(remainders, moduli):
        Ni = N // n
        inv = pow(Ni, -1, n)  # modular inverse
        x = (x + r * Ni * inv) % N
    return x, N


def recv_json_capsule(sock, buffer):
    """
    Receive one JSON object line (time capsule) from the socket.
    We may have leftover prompt text in 'buffer', so we:
      - read until we see '\n'
      - take the part before the first '\n' as 'line'
      - strip any leading junk before '{'
    Returns (capsule_dict, new_buffer).
    """
    while b'\n' not in buffer:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Connection closed by remote host")
        buffer += chunk

    line, buffer = buffer.split(b'\n', 1)

    # Strip anything before the first '{'
    idx = line.find(b'{')
    if idx != -1:
        line = line[idx:]

    capsule = json.loads(line.decode())
    return capsule, buffer


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <host> [port]")
        print("Default port is 1337")
        host = "127.0.0.1"
        port = 1337
    else:
        host = sys.argv[1]
        port = int(sys.argv[2]) if len(sys.argv) >= 3 else 1337

    print(f"[+] Connecting to {host}:{port}")
    s = socket.create_connection((host, port))
    buf = b""

    moduli = []
    ciphers = []

    try:
        while len(moduli) < E:
            # Ask for a new time capsule
            s.sendall(b"Y\n")

            capsule, buf = recv_json_capsule(s, buf)

            c_hex = capsule["time_capsule"]
            n_hex, e_hex = capsule["pubkey"]

            c = int(c_hex, 16)
            n = int(n_hex, 16)
            e = int(e_hex, 16)

            assert e == E, f"Unexpected exponent {e}, expected {E}"

            # Ensure moduli are pairwise coprime (very likely, but just in case)
            if any(math.gcd(n, ni) != 1 for ni in moduli):
                print("[!] Got non-coprime modulus, discarding and trying again...")
                continue

            moduli.append(n)
            ciphers.append(c)
            print(f"[+] Got capsule {len(moduli)}/{E}")

        # We're done, tell the server we don't want more
        s.sendall(b"N\n")
    finally:
        s.close()

    print("[+] Performing CRT on the ciphertexts...")
    M_e, N = crt(ciphers, moduli)

    print("[+] Taking the integer 5th root...")
    M, exact = iroot(E, M_e)
    if not exact:
        print("[!] Warning: root is not exact (possible error!), but continuing.")

    flag_bytes = long_to_bytes(M)
    try:
        flag_str = flag_bytes.decode()
    except UnicodeDecodeError:
        flag_str = flag_bytes.decode(errors="replace")

    print("[+] Recovered flag (raw bytes):", flag_bytes)
    print("[+] Recovered flag (string):", flag_str)


if __name__ == "__main__":
    main()
