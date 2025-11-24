#!/usr/bin/env python3

import numpy as np

CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_"
EMOJI_SEG = ['😀', '😃', '😄', '😁']

def load_weights(path="weights.npz"):
    data = np.load(path)
    W = data["W"]  # shape (len(CHARSET), 8)
    return W

def decode_emoji_group(emoji_group: str, W: np.ndarray) -> str:
    """Decode a 4-emoji group back to a character."""
    # Each emoji group represents one character (8 bits = 4 emojis of 2 bits each)
    if len(emoji_group) != 4:
        raise ValueError(f"Expected 4 emojis, got {len(emoji_group)}")
    
    # Convert emojis back to 2-bit segments
    code = 0
    for emoji in emoji_group:
        if emoji not in EMOJI_SEG:
            raise ValueError(f"Unknown emoji: {emoji}")
        seg_value = EMOJI_SEG.index(emoji)
        code = (code << 2) | seg_value
    
    # Now we have an 8-bit code, we need to find which character it matches
    # Convert code to bits
    bits = []
    for i in range(7, -1, -1):
        bits.append((code >> i) & 1)
    bits = np.array(bits, dtype=np.int32)
    
    # Find matching character by comparing with weight matrix
    for idx, ch in enumerate(CHARSET):
        logits = W[idx]
        char_bits = (logits > 0).astype(np.int32)
        if np.array_equal(bits, char_bits):
            return ch
    
    raise ValueError(f"No matching character found for code: {code:08b}")

def decode_text(emoji_text: str, W: np.ndarray) -> str:
    """Decode emoji text back to original string."""
    # Split into groups of 4 emojis
    emoji_list = list(emoji_text.strip())
    
    if len(emoji_list) % 4 != 0:
        raise ValueError(f"Emoji count must be multiple of 4, got {len(emoji_list)}")
    
    result = []
    for i in range(0, len(emoji_list), 4):
        emoji_group = "".join(emoji_list[i:i+4])
        char = decode_emoji_group(emoji_group, W)
        result.append(char)
    
    return "".join(result)

def main():
    W = load_weights()
    
    # Read the secret output
    with open("secret_output.txt", "r", encoding="utf-8") as f:
        emoji_text = f.read().strip()
    
    print(f"Encoded message: {emoji_text}")
    print(f"Number of emojis: {len(emoji_text)}")
    print(f"Number of characters: {len(emoji_text) // 4}")
    print()
    
    try:
        decoded = decode_text(emoji_text, W)
        print(f"Decoded message: {decoded}")
    except Exception as e:
        print(f"Error decoding: {e}")

if __name__ == "__main__":
    main()
