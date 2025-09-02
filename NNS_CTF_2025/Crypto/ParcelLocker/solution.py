from Crypto.Util.number import long_to_bytes, bytes_to_long
import requests
import time

# Given values (Replace them)
sig_hex = "0x9dd93e9f69cd9cce84c035e2c68d57afe53131973303ee5a3de777b2ad49026"
n_hex = "0x8301d635d7ebe199a17b291f9eb4ffc285809e62d7cb3ad3f72e2eaf384a149b"
e_hex = "0x10001"
base_url = "https://95cdca5e-edc6-473d-8b28-6e8564653b38.chall.nnsc.tf/api/open/"

# Convert to integers
n = int(n_hex, 16)
e = int(e_hex, 16)
sig_given = int(sig_hex, 16)

# Factors from FactorDB (Replace them)
p = 241981648356534820147458727896587837401
q = 244879018054705304626023783215173747603

# Compute phi and d
phi = (p-1) * (q-1)
d = pow(e, -1, phi)

# Message function: always two digits
def get_message(slot_id):
    return str(slot_id).zfill(2)

# Sign a message for a given slot
def sign_slot(slot_id):
    msg = get_message(slot_id)
    msg_int = int.from_bytes(msg.encode('utf-8'), 'big')
    sig = pow(msg_int, d, n)
    return hex(sig)

# Verify for slot 2
sig_calculated = sign_slot(2)
if sig_calculated == sig_hex:
    print("Signature for slot 2 matches!")
else:
    print(f"Signature mismatch for slot 2: calculated {sig_calculated}, given {sig_hex}")

# Now try to open all slots from 0 to 35 to find the flag
for slot_id in range(0, 36):
    sig_hex_val = sign_slot(slot_id)
    url = f"{base_url}{slot_id}?sig={sig_hex_val}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            print(f"Slot {slot_id}: {data}")
            if "flag" in data['content']:
                print(f"Flag found in slot {slot_id}: {data['content']}")
                break
        else:
            print(f"Error for slot {slot_id}: HTTP {response.status_code}")
    except Exception as e:
        print(f"Error for slot {slot_id}: {e}")
    time.sleep(0.5)  # Avoid rate limiting