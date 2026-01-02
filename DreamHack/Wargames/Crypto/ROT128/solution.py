#!/usr/bin/env python3

# Read the encrypted hex string
with open('encfile', 'r', encoding='utf-8') as f:
    enc_s = f.read()

# Parse hex string into pairs (each pair = one byte)
enc_list = [enc_s[i:i+2] for i in range(0, len(enc_s), 2)]

# Create hex lookup table
hex_list = [(hex(i)[2:].zfill(2).upper()) for i in range(256)]

# Decrypt by applying ROT128 again (it's its own inverse)
dec_list = []
for hex_b in enc_list:
    index = hex_list.index(hex_b)
    dec_byte = (index + 128) % 256
    dec_list.append(dec_byte)

# Write decrypted bytes back to a PNG file
with open('flag.png', 'wb') as f:
    f.write(bytes(dec_list))

print("Decrypted to flag.png")
