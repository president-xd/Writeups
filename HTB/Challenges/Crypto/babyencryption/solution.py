#!/usr/bin/env python3

def decrypt(ct: bytes) -> bytes:
    INV = 179  # correct modular inverse of 123 mod 256
    pt = []
    for c in ct:
        m = (INV * ((c - 18) % 256)) % 256
        pt.append(m)
    return bytes(pt)


def main():
    # Read encrypted hex file
    with open("./msg.enc", "r") as f:
        data = f.read().strip()

    # Convert hex → bytes
    ct = bytes.fromhex(data)

    # Decrypt
    pt = decrypt(ct)

    print("Decrypted bytes:", pt)
    try:
        print("As string:", pt.decode())
    except UnicodeDecodeError:
        print("Could not decode to UTF-8 string, here is latin-1 decode:")
        print(pt.decode("latin-1"))


if __name__ == "__main__":
    main()
