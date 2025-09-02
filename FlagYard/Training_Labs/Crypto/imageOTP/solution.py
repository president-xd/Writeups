#!/usr/bin/env python3
import os
import sys
import re
from pathlib import Path

# Optional OCR: these imports are guarded so the script still runs without OCR
HAVE_PIL = True
try:
    from PIL import Image
except Exception:
    HAVE_PIL = False

HAVE_OCR = True
try:
    import pytesseract
    # sanity check: will raise if tesseract is missing
    try:
        _ = pytesseract.get_tesseract_version()
    except Exception:
        HAVE_OCR = False
except Exception:
    HAVE_OCR = False

def xor_bytes(b1: bytes, b2: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(b1, b2))

def row_size_bytes(width: int, bpp: int = 24) -> int:
    # BMP rows are padded to 4-byte boundaries
    return ((bpp * width + 31) // 32) * 4

def build_bmp_header(width: int, height: int, bpp: int = 24) -> bytes:
    # BITMAPFILEHEADER (14) + BITMAPINFOHEADER (40) = 54 bytes
    # We’ll construct the simplest 24bpp, BI_RGB (no compression) header
    header_size = 14
    dib_size = 40
    pixel_offset = header_size + dib_size
    stride = row_size_bytes(width, bpp)
    image_size = stride * height
    file_size = pixel_offset + image_size

    # --- FILE HEADER ---
    bfType = b'BM'                                   # 0x42,0x4D
    bfSize = file_size.to_bytes(4, 'little')         # total file size
    bfReserved1 = (0).to_bytes(2, 'little')
    bfReserved2 = (0).to_bytes(2, 'little')
    bfOffBits = pixel_offset.to_bytes(4, 'little')   # start of pixel array

    file_header = bfType + bfSize + bfReserved1 + bfReserved2 + bfOffBits

    # --- DIB (BITMAPINFOHEADER) ---
    biSize = dib_size.to_bytes(4, 'little')
    biWidth = width.to_bytes(4, 'little', signed=True)
    biHeight = height.to_bytes(4, 'little', signed=True)  # positive = bottom-up
    biPlanes = (1).to_bytes(2, 'little')
    biBitCount = (bpp).to_bytes(2, 'little')
    biCompression = (0).to_bytes(4, 'little')        # BI_RGB
    biSizeImage = image_size.to_bytes(4, 'little')   # can be 0 for BI_RGB, but we fill it
    biXPelsPerMeter = (2835).to_bytes(4, 'little')   # ~72 DPI
    biYPelsPerMeter = (2835).to_bytes(4, 'little')
    biClrUsed = (0).to_bytes(4, 'little')
    biClrImportant = (0).to_bytes(4, 'little')

    dib = (biSize + biWidth + biHeight + biPlanes + biBitCount +
           biCompression + biSizeImage + biXPelsPerMeter +
           biYPelsPerMeter + biClrUsed + biClrImportant)

    return file_header + dib  # 54 bytes

def save_bmp_from_pixels(out_path: Path, pixels: bytes, width: int, height: int, bpp: int = 24) -> bool:
    """Create a valid BMP file with given width/height from raw BGR pixel data (bottom-up)."""
    stride = row_size_bytes(width, bpp)
    expected = stride * height
    if len(pixels) != expected:
        return False

    header = build_bmp_header(width, height, bpp)
    out_path.write_bytes(header + pixels)
    return True

def generate_candidates(xor_body: bytes, out_dir: Path, bpp: int = 24, max_outputs: int = 50):
    """
    Try plausible width/height combos that exactly fit the XOR pixel data with BMP stride constraints.
    Writes up to max_outputs images into out_dir and returns a list of paths.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    n = len(xor_body)
    candidates = []

    # Heuristics for width search:
    #   - Try common widths first, then scan a range.
    common_widths = [
        128, 160, 192, 200, 240, 256, 320, 360, 400, 480, 512, 600, 640, 720,
        800, 960, 1024, 1080, 1200, 1280, 1440, 1600
    ]
    tried = set()

    def try_width(w):
        if w in tried:
            return
        tried.add(w)
        stride = row_size_bytes(w, bpp)
        if stride == 0 or n % stride != 0:
            return
        h = n // stride
        # keep only "reasonable" shapes
        aspect = w / max(h, 1)
        if 0.3 <= aspect <= 3.5 and h > 10:
            # BMP stores pixels bottom-up; xor_body likely already in bottom-up order from BMPs
            out_path = out_dir / f"xor_{w}x{h}.bmp"
            if save_bmp_from_pixels(out_path, xor_body, w, h, bpp):
                candidates.append(out_path)

    # Try common widths
    for w in common_widths:
        try_width(w)
        if len(candidates) >= max_outputs:
            return candidates

    # Fallback: brute force a range (bounded to avoid explosion)
    # Try widths from 64..2048 stepping by 2 to keep even widths (common in BMPs)
    for w in range(64, 2049, 2):
        try_width(w)
        if len(candidates) >= max_outputs:
            break

    return candidates

def ocr_and_find_flags(img_path: Path):
    if not (HAVE_OCR and HAVE_PIL):
        return None, None  # OCR not available
    try:
        text = pytesseract.image_to_string(Image.open(img_path))
        text = (text or "").strip()
        if not text:
            return "", []
        flags = re.findall(r"FlagY\{[^}]*\}", text)
        return text, flags
    except Exception:
        return None, None

def main():
    if len(sys.argv) != 3:
        print(f"Usage: python {Path(__file__).name} <flag.bmp.enc> <tux.bmp.enc>")
        sys.exit(1)

    p1 = Path(sys.argv[1])
    p2 = Path(sys.argv[2])
    if not p1.exists() or not p2.exists():
        print("[!] One or both input files do not exist.")
        sys.exit(1)

    c1 = p1.read_bytes()
    c2 = p2.read_bytes()
    if len(c1) != len(c2):
        print("[!] Inputs differ in length; XOR will truncate to the shorter length.")

    xored = xor_bytes(c1, c2)
    Path("xored.bin").write_bytes(xored)
    print("[+] XOR done. Wrote raw XOR bytes to 'xored.bin'.")

    # For BMPs with identical headers, the first 54 bytes will XOR to zeros.
    if xored[:54] != b"\x00" * min(54, len(xored)):
        print("[!] Warning: First 54 bytes are not all zero. Headers might differ.")
    else:
        print("[+] Detected identical headers (first 54 XOR to zeros).")

    # Build candidate BMPs from the XORed **pixel data** (skip 54-byte headers)
    xor_body = xored[54:]
    out_dir = Path("candidates")
    candidates = generate_candidates(xor_body, out_dir, bpp=24, max_outputs=80)

    if not candidates:
        print("[-] No plausible BMP candidates were generated. "
              "You can tweak width heuristics or try bpp=32 in the code.")
        sys.exit(0)

    print(f"[+] Wrote {len(candidates)} BMP candidates to '{out_dir}/'. "
          "Open them and look for readable text (e.g., a flag).")

    any_ocr = False
    for i, img_path in enumerate(candidates, 1):
        if HAVE_OCR and HAVE_PIL:
            any_ocr = True
            text, flags = ocr_and_find_flags(img_path)
            if text is None:
                print(f"    [{i:02}] {img_path.name}: OCR not available/failed.")
            else:
                if flags:
                    print(f"    [{i:02}] {img_path.name}: FOUND {len(flags)} flag(s): {', '.join(flags)}")
                    # If you want to stop at first hit, uncomment:
                    # break
                elif text:
                    # Print a short preview
                    snippet = text.replace("\n", " ").strip()
                    if len(snippet) > 100:
                        snippet = snippet[:100] + "..."
                    print(f"    [{i:02}] {img_path.name}: OCR text preview -> {snippet}")
                else:
                    print(f"    [{i:02}] {img_path.name}: (no OCR text)")
        else:
            # OCR not available; at least list the candidates
            print(f"    [{i:02}] {img_path.name}")

    if not any_ocr:
        print("[i] OCR not run (install Pillow + pytesseract + Tesseract to enable).")

if __name__ == "__main__":
    main()
