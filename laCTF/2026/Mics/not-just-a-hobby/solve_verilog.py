#!/usr/bin/env python3
"""
Parse Verilog VGA module and render the hidden flag image.

Key insight: inputs are [6:0] (7 bits, 0-127) but literals are larger.
All coordinate values must be taken mod 128 to get the real pixel positions.
"""
import re
from PIL import Image

VERILOG_FILE = r"c:\Users\president\Downloads\v.v"

# Parse all (x == VAL && y == VAL) pairs, respecting Verilog width rules:
#   7'd<N> -> truncated to 7 bits (N & 0x7F)
#   plain <N> -> 32-bit literal; if N > 127, comparison with 7-bit signal is always false
pattern = re.compile(
    r"\(x\s*==\s*(7'd)?(\d+)\s*&&\s*y\s*==\s*(7'd)?(\d+)\)"
)

pixels = set()
with open(VERILOG_FILE, "r") as f:
    text = f.read()

for m in pattern.finditer(text):
    x_prefix, x_val, y_prefix, y_val = m.group(1), int(m.group(2)), m.group(3), int(m.group(4))
    
    if x_prefix:  # has 7'd prefix -> truncate to 7 bits
        x = x_val & 0x7F
    else:  # plain integer, 32-bit
        if x_val > 127:
            continue  # always false, skip
        x = x_val
    
    if y_prefix:
        y = y_val & 0x7F
    else:
        if y_val > 127:
            continue
        y = y_val
    
    pixels.add((x, y))

print(f"Found {len(pixels)} unique pixels (after mod 128)")

# Find bounding box
if pixels:
    xs = [p[0] for p in pixels]
    ys = [p[1] for p in pixels]
    print(f"X range: {min(xs)}-{max(xs)}, Y range: {min(ys)}-{max(ys)}")

# Create 128x128 image (white background, black pixels)
W, H = 128, 128
img = Image.new("RGB", (W, H), (255, 255, 255))

for (x, y) in pixels:
    img.putpixel((x, y), (0, 0, 0))

# Save scaled-up version for readability
scale = 4
img_big = img.resize((W * scale, H * scale), Image.NEAREST)
out_path = r"d:\LLLL\flag_image.png"
img_big.save(out_path)
print(f"Saved to {out_path}")

# Also try ASCII art rendering for quick look
print("\nASCII render (128 cols):")
for row in range(H):
    line = ""
    for col in range(W):
        if (col, row) in pixels:
            line += "##"
        else:
            line += "  "
    # Only print rows that have pixels
    if "##" in line:
        print(f"{row:3d}: {line.rstrip()}")
