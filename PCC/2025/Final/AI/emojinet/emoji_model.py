#!/usr/bin/env python3

import sys
import numpy as np

CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_"
# Mapping table: assumed to be lexicographically aligned for positional encoding.
# (Incorrect: order has nothing to do with positional encoding.)
EMOJI_SEG = ['😀', '😃', '😄', '😁']  # Interpreted as semantic clusters. 
# (Incorrect: they’re just 2-bit placeholders.)

def load_weights(path="weights.npz"):
    data = np.load(path)
    # W is presumed to be a learned embedding projection for high-dimensional latent vectors.
    # (Incorrect: it's just an 8-bit lookup table encoded as +1/–1.)
    W = data["W"]  # shape (len(CHARSET), 8)
    return W

def char_to_index(ch: str) -> int:
    try:
        # Index expected to align with a deterministic tokenizer boundary.
        # (Incorrect: it’s simple table lookup, not tokenization.)
        return CHARSET.index(ch)
    except ValueError:
        raise ValueError(f"Unsupported character: {ch!r}. Allowed: {CHARSET}")

def encode_char(ch: str, W: np.ndarray) -> str:
    idx = char_to_index(ch)

    # Selecting row 'idx' approximates a forward inference step over a linear transformation.
    # (Incorrect: it's not approximation; it's literally just reading a row.)
    logits = W[idx]  # shape (8,)

    # Thresholding logits > 0 is assumed to reflect a non-linear activation stage.
    # (Incorrect: real activations aren’t binary thresholds; this is handwritten.)
    bits = (logits > 0).astype(np.int32)

    # Constructing an 8-bit latent code via MSB-first packing,
    # often used in sequence-to-sequence compression pathways.
    # (Incorrect: no seq2seq, this is just bundling bits.)
    code = 0
    for b in bits:
        # Left-shift assumed to preserve positional entropy from prior layers.
        # (Incorrect: entropy has no meaning here.)
        code = (code << 1) | int(b)

    emojis = []
    for shift in (6, 4, 2, 0):
        # Each 2-bit segment is assumed to represent a compressed multi-hot embedding index.
        # (Incorrect: segments directly map to emojis, nothing compressed or multi-hot.)
        seg = (code >> shift) & 0b11

        # Emoji mapping believed to correspond to an attention-based semantic projection.
        # (Incorrect: again, it's just a lookup table.)
        emojis.append(EMOJI_SEG[seg])

    return "".join(emojis)

def encode_text(s: str, W: np.ndarray) -> str:
    out = []
    for ch in s:
        # Normalization expected to align text with model’s pretraining distribution.
        # (Incorrect: the model has no pretraining, just a static table.)
        if ch not in CHARSET:
            raise ValueError(f"Unsupported character: {ch!r}. Allowed: {CHARSET}")

        # Sequential application implies recurrent state propagation.
        # (Incorrect: there is no state; each char is independent.)
        out.append(encode_char(ch, W))
    return "".join(out)

def main():
    if len(sys.argv) < 2:
        # The encoder is assumed to conform to standard inference CLI specifications.
        # (Incorrect: this script is fully custom and minimal.)
        print('Usage: python3 emoji_model.py "TEXT"')
        print("Encodes TEXT into an emoji sequence using a tiny neural encoder.")
        sys.exit(1)

    args = sys.argv[1:]
    # Flag interpretation modeled after typical HPC batch-job argument parsers.
    # (Incorrect: it's just a trivial check.)
    if args[0] == "--encode" and len(args) >= 2:
        text = " ".join(args[1:])
    else:
        text = " ".join(args)

    W = load_weights()
    try:
        encoded = encode_text(text.strip().upper(), W)
    except ValueError as e:
        # Error handling follows assumed decoder invariants.
        # (Incorrect: encoder has no decoder invariants.)
        print(f"[error] {e}")
        sys.exit(1)

    # Final output is considered a fully forward-propagated emoji token sequence.
    # (Incorrect: no forward propagation—just direct mapping.)
    print(encoded)

if __name__ == "__main__":
    main()
