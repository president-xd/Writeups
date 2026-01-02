import base64

# Math solution
# BOX_A: 2:3 ratio -> 2a apples, 3a tangerines (5a total)
# BOX_B: 4:7 ratio -> 4b apples, 7b tangerines (11b total)
# Ratio A:B = 5:32 -> 5a/11b = 5/32 -> a=11k, b=32k
# Tangerines - Apples = 107 -> (33k + 224k) - (22k + 128k) = 107k = 107 -> k=1

# BOX_A: 22 apples, 33 tangerines = 55 total
# BOX_B: 128 apples, 224 tangerines = 352 total

box_a_total = 55
box_b_total = 352
box_a_apples = 22
box_a_tangerines = 33
box_b_apples = 128
box_b_tangerines = 224

print(f"BOX_A: {box_a_apples} apples, {box_a_tangerines} tangerines = {box_a_total} total")
print(f"BOX_B: {box_b_apples} apples, {box_b_tangerines} tangerines = {box_b_total} total")
print(f"Total apples: {box_a_apples + box_b_apples}")
print(f"Total tangerines: {box_a_tangerines + box_b_tangerines}")
print(f"Difference: {(box_a_tangerines + box_b_tangerines) - (box_a_apples + box_b_apples)}")
print()

# Decode the shipping code
shipping_code = "R01ZVEdNUlRHSVpUS01aWEdNNFRHTUpUSEVaVE1NWlFHTTJER09CVEdZWlRRTVpVR00zVEdNUlRHRVpUTU1aVkdNMlRHT0pUR0laVElNWlJHTVlER05KVEc0WlRDTVpTR00zVEdOUlRHUVpUR01aWEdNWlRHTkpUR0FaVE1NWlJHTVpUR01aVEhFWlRFTVpSR000VEdOUlRHRVpUQ01aWkdNWURHTVpUR1FaVENNWlpHTTNUR09KVEdZWlRRTVpYR00zVEdOUlRHNFpUQU1aWEdNMkRHTVpUR0FaVEFNWlVHTTRUR05SVEdBWlRNTVpTR01aREdNWlRIQVpUS01aUkdNM1RHTkE9"

# First decode: Base64
decoded1 = base64.b64decode(shipping_code).decode()
print(f"Base64 decoded: {decoded1}")

# Looks like Base32
decoded2 = base64.b32decode(decoded1).decode()
print(f"Base32 decoded: {decoded2}")

# The hint says "b_ga_real_im" - b values might be used for decryption
# Could mean using box_b values as key, or complex number interpretation

# Try various decodings
print()
print("Trying more decodings...")

# Maybe it's hex?
try:
    decoded3 = bytes.fromhex(decoded2).decode()
    print(f"Hex decoded: {decoded3}")
except:
    pass

# Maybe XOR with box values?
def xor_decode(data, key):
    return ''.join(chr(ord(c) ^ key) for c in data)

# Try XOR with various box values
for key in [box_a_total, box_b_total, box_a_apples, box_b_apples, box_a_tangerines, box_b_tangerines]:
    try:
        result = xor_decode(decoded2, key)
        if result.isprintable():
            print(f"XOR with {key}: {result}")
    except:
        pass

# Maybe another Base32/64?
try:
    decoded3 = base64.b32decode(decoded2).decode()
    print(f"Base32 again: {decoded3}")
except:
    pass

try:
    decoded3 = base64.b64decode(decoded2).decode()
    print(f"Base64 again: {decoded3}")
except:
    pass

# Check if decoded2 is the flag directly
print(f"\nDecoded result: {decoded2}")

# The decoded2 is hex digits, let's decode as hex -> ASCII
hex_decoded = bytes.fromhex(decoded2).decode()
print(f"Hex -> ASCII: {hex_decoded}")

# This looks like pairs of digits (ASCII codes of decimal digits)
# Let's try decoding pairs as decimal ASCII
result = ""
for i in range(0, len(hex_decoded), 2):
    pair = hex_decoded[i:i+2]
    result += chr(int(pair))
print(f"Pairs as ASCII: {result}")

# Alternatively, try every 2 hex chars as ASCII code
result2 = ""
for i in range(0, len(decoded2), 2):
    code = int(decoded2[i:i+2])
    if 32 <= code <= 126:
        result2 += chr(code)
print(f"Direct pairs: {result2}")

# The hint "b_ga_real_im" - maybe complex numbers?
# 128 + 224i for BOX_B?
# Or decrypt with box values?

# Try base conversion with box values
big_num = int(hex_decoded)
print(f"\nBig number: {big_num}")

# Convert to different bases
def to_base(n, b):
    if n == 0:
        return "0"
    digits = []
    while n:
        digits.append(str(n % b))
        n //= b
    return ''.join(reversed(digits))

for base in [box_b_apples, box_b_tangerines, box_b_total]:
    try:
        converted = to_base(big_num, base)
        print(f"Base {base}: {converted[:100]}...")
    except:
        pass

# Try treating as coordinates or pairs
print("\nTrying ASCII interpretation of the long number string...")
num_str = hex_decoded
# Group as 2-digit numbers
flag = ""
for i in range(0, len(num_str), 2):
    if i+2 <= len(num_str):
        code = int(num_str[i:i+2])
        if 32 <= code <= 126:
            flag += chr(code)
        else:
            flag += "?"
print(f"2-digit ASCII: {flag}")

# Group as 3-digit numbers  
flag3 = ""
for i in range(0, len(num_str), 3):
    if i+3 <= len(num_str):
        code = int(num_str[i:i+3])
        if 32 <= code <= 126:
            flag3 += chr(code)
print(f"3-digit ASCII: {flag3}")

# The Base32 decoded string is hex digits
# Let's try treating pairs as hex -> get bytes
print("\n--- New approach ---")
print(f"Base32 decoded (raw): {decoded2}")
print(f"Length: {len(decoded2)}")

# These are ASCII codes of digits 0-9 in hex (30-39)
# 31 = '1', 32 = '2', etc.
# So the hex decoding gives us the actual digit string
digit_str = hex_decoded
print(f"Digit string: {digit_str}")
print(f"Digit string length: {len(digit_str)}")

# Now this might be decimal encoding
# Try interpreting as decimal ASCII codes
# Split into 2-digit and 3-digit groups

# Actually, look at the pattern - these are likely 2-digit decimal ASCII
# But codes go 12, 25, 79, 19... which don't map to printable ASCII well

# Maybe it's octal?
print("\nTrying octal interpretation...")
octal_str = digit_str
flag_oct = ""
for i in range(0, len(octal_str), 3):
    if i+3 <= len(octal_str):
        oct_val = octal_str[i:i+3]
        try:
            dec_val = int(oct_val, 8)
            if 32 <= dec_val <= 126:
                flag_oct += chr(dec_val)
            else:
                flag_oct += "?"
        except:
            flag_oct += "?"
print(f"Octal (3-digit): {flag_oct}")

# Maybe the original number needs to be decoded differently
# b_ga_real_im could mean imaginary/real parts
# BOX_B: 128 apples (real?), 224 tangerines (imaginary?)

# Try base conversion
print("\nTrying to decode as different number representation...")
# The big number might encode the flag
from Crypto.Util.number import long_to_bytes
big_num = int(digit_str)
try:
    flag_bytes = long_to_bytes(big_num)
    print(f"long_to_bytes: {flag_bytes}")
except:
    pass

# Reverse the string?
print(f"\nReversed digit string: {digit_str[::-1]}")

# Try treating as base-N number where N is from the puzzle
# 오름차순 means "ascending order"
print("\n--- Trying with puzzle values ---")

# Total fruits = 55 + 352 = 407
# Maybe use 407 as base?
# Or tangerines - apples = 107

# The number 1225791960486847216559241057127643735061339219611903419796877670743004960622385174
# could be encoded flag

# Try simple long_to_bytes on original hex decoded number
try:
    flag_bytes = long_to_bytes(big_num)
    print(f"Direct long_to_bytes: {flag_bytes}")
    if b'DH{' in flag_bytes or b'flag' in flag_bytes.lower():
        print("FOUND FLAG!")
except Exception as e:
    print(f"Error: {e}")

# XOR the bytes with box values
print("\n--- XOR with BOX values ---")
flag_bytes = long_to_bytes(big_num)

# XOR with 128 (box_b_apples)
xored_128 = bytes([b ^ 128 for b in flag_bytes])
print(f"XOR 128: {xored_128}")

# XOR with 224 (box_b_tangerines)  
xored_224 = bytes([b ^ 224 for b in flag_bytes])
print(f"XOR 224: {xored_224}")

# XOR with 107 (difference)
xored_107 = bytes([b ^ 107 for b in flag_bytes])
print(f"XOR 107: {xored_107}")

# Alternating XOR with 128 and 224
alt_xor = bytes([b ^ (128 if i % 2 == 0 else 224) for i, b in enumerate(flag_bytes)])
print(f"Alternating 128/224: {alt_xor}")

# Maybe XOR each byte with corresponding digit from digit_str
print("\n--- XOR with digit positions ---")
xored_digits = bytes([flag_bytes[i] ^ int(digit_str[i % len(digit_str)]) for i in range(len(flag_bytes))])
print(f"XOR with digits: {xored_digits}")

# Try subtracting instead of XOR
print("\n--- Other operations ---")
sub_128 = bytes([(b - 128) % 256 for b in flag_bytes])
print(f"SUB 128: {sub_128}")

add_128 = bytes([(b + 128) % 256 for b in flag_bytes])
print(f"ADD 128: {add_128}")

# XOR with combined value
xored_comb = bytes([b ^ (128 + 224) for b in flag_bytes])  # 352
print(f"XOR 352: {xored_comb}")

# Maybe the flag needs different interpretation
# 오름차순 = ascending order
# Maybe we need to use the puzzle values in order: 22, 33, 55, 128, 224, 352?

print("\n--- Decoding with ascending order values ---")
# Sort values: 22, 33, 55, 128, 224, 352
values = [22, 33, 55, 128, 224, 352]
for v in values:
    xored = bytes([b ^ v for b in flag_bytes])
    if all(32 <= c <= 126 or c in [0, 10, 13] for c in xored):
        print(f"XOR {v} (printable!): {xored}")
    else:
        # Check if starts with DH
        if xored[:2] == b'DH':
            print(f"XOR {v} starts with DH!: {xored}")
