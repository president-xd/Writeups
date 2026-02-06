import socket
import ssl
import base64
import re

HOST = "dum-cows.ctf.prgy.in"
PORT = 1337


def connect():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((HOST, PORT), timeout=10)
    return ctx.wrap_socket(raw, server_hostname=HOST)


def recvuntil(sock, marker, timeout=5):
    sock.settimeout(timeout)
    data = b""
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if marker.encode() in data:
                break
        except socket.timeout:
            break
    return data.decode(errors="replace")


def recvall(sock, timeout=3):
    sock.settimeout(timeout)
    data = b""
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        except socket.timeout:
            break
    return data.decode(errors="replace")


def b64dec(s):
    s = s.strip()
    pad = 4 - len(s) % 4
    if pad < 4:
        s += "=" * pad
    return base64.b64decode(s)


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


magic = "FIX_COW moooooooooooomfT_T"

# ==================== STEP 1: Get full keystream from fresh connection ====================
print("STEP 1: Extract keystream (1000 A's)")
sock1 = connect()
recvuntil(sock1, "Give your cow a name:")
sock1.sendall(("A" * 1000 + "\n").encode())
resp1 = recvuntil(sock1, "Give your cow a name:")
m1 = re.search(r'\[Name:\s*([^\]]+?)\]\s*says:\s*(\S+)', resp1)
enc_n1_bytes = b64dec(m1.group(1).strip())
enc_s1_bytes = b64dec(m1.group(2).strip())
ks_name = xor_bytes(b"A" * 1000, enc_n1_bytes)
ks_says = xor_bytes(b"moooooooooooomfT_T", enc_s1_bytes)
full_ks = ks_name + ks_says  # ks[0:1018]
print(f"  Full keystream: {len(full_ks)} bytes: {full_ks[:16].hex()}...")
sock1.close()


# ==================== STEP 2: Magic then known plaintext in SAME connection ====================
print("\nSTEP 2: Magic command then 500 A's in SAME connection")
sock2 = connect()
recvuntil(sock2, "Give your cow a name:")

# Send magic
sock2.sendall((magic + "\n").encode())
# Read the flag response (no "Give your cow a name:" prompt expected immediately)
flag_resp = recvall(sock2, timeout=4)
print(f"  Flag response ({len(flag_resp)} chars):")
print(f"  {repr(flag_resp[:300])}")

flag_match = re.search(r'FLAG SPEAKS:\s*(\S+)', flag_resp)
flag_ct = None
if flag_match:
    flag_b64 = flag_match.group(1)
    flag_ct = b64dec(flag_b64)
    print(f"\n  Flag ciphertext ({len(flag_ct)} bytes): {flag_ct.hex()}")

# Check if there's a prompt in the flag response
if "Give your cow a name:" in flag_resp:
    print("  Prompt found in flag response!")
else:
    print("  No prompt in flag response. Waiting for it...")
    extra = recvuntil(sock2, "Give your cow a name:", timeout=5)
    if "Give your cow a name:" in extra:
        print("  Got delayed prompt!")
    else:
        print(f"  Still no prompt. Extra: {repr(extra[:100])}")

# Now send 500 A's
sock2.sendall(("A" * 500 + "\n").encode())
resp2 = recvuntil(sock2, "Give your cow a name:", timeout=5)
m2 = re.search(r'\[Name:\s*([^\]]+?)\]\s*says:\s*(\S+)', resp2)

if m2:
    enc_n2_bytes = b64dec(m2.group(1).strip())
    enc_s2_bytes = b64dec(m2.group(2).strip())
    ks_post_magic = xor_bytes(b"A" * min(500, len(enc_n2_bytes)), enc_n2_bytes)
    print(f"\n  Post-magic keystream ({len(ks_post_magic)} bytes): {ks_post_magic[:16].hex()}...")
    
    # ==================== STEP 3: Find offset by sliding window ====================
    print("\nSTEP 3: Find magic consumption by matching keystream")
    
    # Find where ks_post_magic[0:20] appears in full_ks
    search_chunk = ks_post_magic[:20]
    found_offset = -1
    for offset in range(len(full_ks) - len(search_chunk)):
        if full_ks[offset:offset+len(search_chunk)] == search_chunk:
            found_offset = offset
            print(f"  MATCH at offset {offset}!")
            print(f"  This means magic consumed {offset} bytes of keystream")
            break
    
    if found_offset == -1:
        print("  No match found! Keystream might differ between connections.")
        print(f"  full_ks[0:16]: {full_ks[:16].hex()}")
        print(f"  post_magic[0:16]: {ks_post_magic[:16].hex()}")
        
        # Maybe the magic triggers a different keystream?
        # Try XOR post-magic ks with full_ks at various offsets to find pattern
        print("\n  Attempting fuzzy match:")
        for offset in range(0, min(200, len(full_ks) - 20)):
            diff = sum(1 for a, b in zip(full_ks[offset:offset+20], search_chunk) if a != b)
            if diff <= 2:  # Allow small differences
                print(f"    Near-match at offset {offset} (diff={diff})")
    else:
        magic_consumed = found_offset
        
        # ==================== STEP 4: Decrypt flag ====================
        print(f"\nSTEP 4: Decrypt flag (magic consumed {magic_consumed} bytes)")
        
        if flag_ct is not None:
            # Try various flag position hypotheses
            hypotheses = [
                ("flag at ks[0:30]", 0),
                ("flag at ks[26:56] (after name)", 26),
                (f"flag at ks[{magic_consumed-30}:{magic_consumed}] (before post-magic)", magic_consumed - 30),
                (f"flag at ks[{magic_consumed-56}:{magic_consumed-26}]", magic_consumed - 56),
            ]
            
            for desc, off in hypotheses:
                if 0 <= off and off + len(flag_ct) <= len(full_ks):
                    dec = xor_bytes(full_ks[off:off+len(flag_ct)], flag_ct)
                    try:
                        text = dec.decode('ascii')
                        printable = all(32 <= b < 127 for b in dec)
                    except:
                        text = dec.hex()
                        printable = False
                    print(f"  {desc}: {text if printable else '[non-printable] ' + dec.hex()[:40]}")
            
            # Also try every offset in range
            print(f"\n  Brute-force all offsets 0..{len(full_ks)-len(flag_ct)}:")
            for off in range(len(full_ks) - len(flag_ct)):
                dec = xor_bytes(full_ks[off:off+len(flag_ct)], flag_ct)
                try:
                    text = dec.decode('ascii')
                    if text.isprintable():
                        print(f"    >>> OFFSET {off}: {text}")
                except:
                    pass
else:
    print("  Could not parse post-magic response!")
    print(f"  Raw: {resp2[:300]}")

sock2.close()

# ==================== STEP 5: Also try says keystream for flag ====================
print("\n" + "=" * 60)
print("STEP 5: What if flag uses says-keystream (separate from name ks)?")
# What if the server has TWO keystreams: one for names, one for says/flag?
# Extract "says keystream" from multiple requests

sock3 = connect()
recvuntil(sock3, "Give your cow a name:")

# Build name-keystream and says-keystream separately
name_ks_parts = []
says_ks_parts = []

for i in range(5):
    length = 100
    name = "A" * length
    sock3.sendall((name + "\n").encode())
    resp = recvuntil(sock3, "Give your cow a name:")
    m = re.search(r'\[Name:\s*([^\]]+?)\]\s*says:\s*(\S+)', resp)
    if m:
        enc_n = b64dec(m.group(1).strip())
        enc_s = b64dec(m.group(2).strip())
        nk = xor_bytes(name.encode()[:len(enc_n)], enc_n)
        sk = xor_bytes(b"moooooooooooomfT_T", enc_s)
        name_ks_parts.append(nk)
        says_ks_parts.append(sk)

sock3.close()

# Build continuous keystream (interleaved name and says)
interleaved_ks = b""
for nk, sk in zip(name_ks_parts, says_ks_parts):
    interleaved_ks += nk + sk

# Build "just says" keystream (concatenation of all says keystreams)  
says_only_ks = b"".join(says_ks_parts)
print(f"  Interleaved ks: {len(interleaved_ks)} bytes")
print(f"  Says-only ks: {len(says_only_ks)} bytes")
print(f"  Name-only ks: {b''.join(name_ks_parts)[:16].hex()}")
print(f"  Says-only ks: {says_only_ks[:16].hex()}")

# Check: is says-keystream just a continuation of the same keystream?
# If so, the first says should be at the same position as in full_ks
if len(says_ks_parts) > 0:
    first_says_ks = says_ks_parts[0]
    # Should match full_ks[100:118] (after 100-byte name)
    if full_ks[100:118] == first_says_ks:
        print("  CONFIRMED: Says uses same continuous keystream as name")
    else:
        print("  Says keystream does NOT match continuous keystream!")
        print(f"    full_ks[100:118]: {full_ks[100:118].hex()}")
        print(f"    first says ks:    {first_says_ks.hex()}")
        
        # Maybe the says keystream is separate!
        # In that case, try decrypting flag with says-keystream
        if flag_ct is not None:
            print("\n  Trying flag decrypt with says-only keystream:")
            for off in range(len(says_only_ks) - len(flag_ct)):
                dec = xor_bytes(says_only_ks[off:off+len(flag_ct)], flag_ct)
                try:
                    text = dec.decode('ascii')
                    if text.isprintable():
                        print(f"    >>> SAYS OFFSET {off}: {text}")
                except:
                    pass

print("\nDONE")

# $env:PYTHONIOENCODING='utf-8'; python D:\LLLL\solve9.py