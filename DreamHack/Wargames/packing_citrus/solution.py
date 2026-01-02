import base64

# Encoded data
encoded = "xBmqfPcZ0tsfZ3mULhMD30IBUai16RZOVEvqtoqCFF9qQ/b="

# === Stage 3: Reverse truck (custom base64) ===
STD_TABLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
MY_TABLE  = STD_TABLE[::-1]

def untruck(data):
    # Reverse the translation (MY_TABLE -> STD_TABLE)
    trans_table = str.maketrans(MY_TABLE, STD_TABLE)
    standard_b64 = data.translate(trans_table)
    return base64.b64decode(standard_b64)

# === Stage 2: Reverse box (XOR with KEY and index) ===
KEY = b"DELICIOUS"

def unbox(data):
    # XOR is its own inverse
    res = []
    for i, b in enumerate(data):
        k = KEY[i % len(KEY)]
        res.append(b ^ k ^ (i & 0xFF))
    return bytes(res)

# === Stage 1: Reverse wrap (affine cipher) ===
# wrap: (b * 13 + 37) % 256
# unwrap: ((b - 37) * inv(13)) % 256
# inv(13) mod 256 = 197 (since 13 * 197 = 2561 = 1 mod 256)

def unwrap(data):
    inv_13 = pow(13, -1, 256)  # = 197
    return bytes([((b - 37) * inv_13) % 256 for b in data])

# Decode in reverse order
step1 = untruck(encoded)
print(f"After untruck: {step1.hex()}")

step2 = unbox(step1)
print(f"After unbox: {step2.hex()}")

step3 = unwrap(step2)
print(f"After unwrap: {step3}")

# Try as string
try:
    flag = step3.decode()
    print(f"\nFlag: {flag}")
except:
    print(f"\nRaw bytes: {step3}")
