import re

phonetic_map = {
    "A":"ALPHA","B":"BRAVO","C":"CHARLIE","D":"DELTA","E":"ECHO",
    "F":"FOXTROT","G":"GOLF","H":"HOTEL","I":"INDIA","J":"JULIETT",
    "K":"KILO","L":"LIMA","M":"MIKE","N":"NOVEMBER","O":"OSCAR",
    "P":"PAPA","Q":"QUEBEC","R":"ROMEO","S":"SIERRA","T":"TANGO",
    "U":"UNIFORM","V":"VICTOR","W":"WHISKEY","X":"XRAY","Y":"YANKEE",
    "Z":"ZULU","_":"UNDERSCORE","{":"OPENCURLYBRACE","}":"CLOSECURLYBRACE",
    "0":"ZERO","1":"ONE","2":"TWO","3":"THREE","4":"FOUR","5":"FIVE",
    "6":"SIX","7":"SEVEN","8":"EIGHT","9":"NINE"
}

# All characters the flag can contain (phonetic_mapping keeps [a-zA-Z0-9_{}])
FLAG_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}"

# Pre-compute "super-words": double phonetic encoding of each character
super_words = {}
for c in FLAG_CHARS:
    first = phonetic_map[c]                                      # e.g. A → ALPHA
    second = "".join(phonetic_map[ch] for ch in first)            # each letter → NATO word
    super_words[c] = second

# Read ciphertext
with open("ct.txt", "r") as f:
    ct = f.read().strip()
ct_bigrams = [ct[i:i+2] for i in range(0, len(ct), 2)]
N = len(ct_bigrams)
print(f"CT: {len(ct)} chars, {N} bigrams\n")

# ── State: known plaintext characters + substitution tables ──────────────────
known = {}          # char_position → plaintext character
sub = {}            # pt_bigram → ct_bigram
inv = {}            # ct_bigram → pt_bigram

def place_superword(pos, sw):
    """Place a super-word at character position pos, update known chars."""
    for j, ch in enumerate(sw):
        known[pos + j] = ch

def sync_mappings():
    """Register any newly-completed bigram mappings."""
    new = 0
    for bi in range(N):
        c0 = known.get(2*bi)
        c1 = known.get(2*bi + 1)
        if c0 is not None and c1 is not None:
            pt = c0 + c1
            ct_bg = ct_bigrams[bi]
            if ct in inv and inv[ct_bg] != pt:
                pass  # conflict — shouldn't happen
            if ct_bg not in inv:
                sub[pt] = ct_bg
                inv[ct_bg] = pt
                new += 1
    return new

def check_consistent(pos, sw):
    """Check if placing super-word sw at pos is consistent with known data."""
    for j, ch in enumerate(sw):
        p = pos + j
        # Check against already-known chars
        if p in known and known[p] != ch:
            return False
    
    # Check bigram mapping consistency
    # We need to temporarily add characters and check bigram mappings
    temp = {}
    for j, ch in enumerate(sw):
        temp[pos + j] = ch
    
    for j in range(len(sw)):
        p = pos + j
        bi = p // 2
        if bi >= N:
            return False  # plaintext extends beyond ciphertext
        c0 = temp.get(2*bi, known.get(2*bi))
        c1 = temp.get(2*bi + 1, known.get(2*bi + 1))
        if c0 is not None and c1 is not None:
            pt_bg = c0 + c1
            ct_bg = ct_bigrams[bi]
            # Check: if this PT bigram was seen before, it must map to the same CT bigram
            if pt_bg in sub and sub[pt_bg] != ct_bg:
                return False
            # Check: if this CT bigram was seen before, it must map to the same PT bigram
            if ct_bg in inv and inv[ct_bg] != pt_bg:
                return False
    return True

# ── Initialize with known prefix "LACTF{" ────────────────────────────────────
pos = 0
for flag_char in "LACTF{":
    sw = super_words[flag_char]
    place_superword(pos, sw)
    pos += len(sw)
sync_mappings()
print(f"After prefix: pos={pos}, mappings={len(sub)}")

# ── Sequentially decode each flag-content character ──────────────────────────
decoded_flag = list("LACTF{")

while True:
    candidates = []
    for c in FLAG_CHARS:
        sw = super_words[c]
        if check_consistent(pos, sw):
            candidates.append(c)
    
    if len(candidates) == 1:
        c = candidates[0]
        decoded_flag.append(c)
        sw = super_words[c]
        place_superword(pos, sw)
        pos += len(sw)
        sync_mappings()
        
        if c == '}':
            print(f"\nDone! Decoded {len(decoded_flag)} characters.")
            break
    elif len(candidates) == 0:
        print(f"\nNo candidates at pos={pos}, decoded so far: {''.join(decoded_flag)}")
        # Maybe we need to handle first-phonetic-mapping padding (X appended if odd)
        # Try inserting an X character (from padding) and continue
        print("Trying padding X...")
        sw_x = super_words['X']
        if check_consistent(pos, sw_x):
            place_superword(pos, sw_x)
            pos += len(sw_x)
            sync_mappings()
            print(f"  Padding X placed at pos {pos - len(sw_x)}")
            continue
        print("Padding X doesn't work either. Stuck.")
        break
    else:
        # Multiple candidates — try look-ahead to disambiguate
        print(f"\nMultiple ({len(candidates)}) candidates at pos={pos}: {candidates}")
        print(f"  Decoded so far: {''.join(decoded_flag)}")
        
        # Try 2-character look-ahead
        resolved = False
        for c1 in candidates:
            sw1 = super_words[c1]
            # Temporarily place c1
            temp_known = dict(known)
            temp_sub = dict(sub)
            temp_inv = dict(inv)
            for j, ch in enumerate(sw1):
                known[pos + j] = ch
            sync_mappings()
            
            # Now try each next character
            next_pos = pos + len(sw1)
            next_ok = []
            for c2 in FLAG_CHARS:
                sw2 = super_words[c2]
                if check_consistent(next_pos, sw2):
                    next_ok.append(c2)
            
            # Restore
            known.clear(); known.update(temp_known)
            sub.clear(); sub.update(temp_sub)
            inv.clear(); inv.update(temp_inv)
            
            if len(next_ok) > 0:
                # c1 is viable
                pass
            else:
                # c1 leads to dead end — remove from candidates
                candidates.remove(c1)
        
        if len(candidates) == 1:
            c = candidates[0]
            decoded_flag.append(c)
            sw = super_words[c]
            place_superword(pos, sw)
            pos += len(sw)
            sync_mappings()
            print(f"  Resolved by look-ahead: {c}")
            if c == '}':
                print(f"\nDone! Decoded {len(decoded_flag)} characters.")
                break
        else:
            print(f"  Still ambiguous after look-ahead: {candidates}")
            # Try deeper look-ahead (3 chars)
            final_candidates = []
            for c1 in candidates:
                sw1 = super_words[c1]
                temp_known = dict(known)
                temp_sub = dict(sub)
                temp_inv = dict(inv)
                for j, ch in enumerate(sw1):
                    known[pos + j] = ch
                sync_mappings()
                
                next_pos = pos + len(sw1)
                viable = False
                for c2 in FLAG_CHARS:
                    sw2 = super_words[c2]
                    if check_consistent(next_pos, sw2):
                        # Try one more level
                        temp2_known = dict(known)
                        temp2_sub = dict(sub)
                        temp2_inv = dict(inv)
                        for j2, ch2 in enumerate(sw2):
                            known[next_pos + j2] = ch2
                        sync_mappings()
                        
                        next2_pos = next_pos + len(sw2)
                        for c3 in FLAG_CHARS:
                            sw3 = super_words[c3]
                            if check_consistent(next2_pos, sw3):
                                viable = True
                                break
                        
                        known.clear(); known.update(temp2_known)
                        sub.clear(); sub.update(temp2_sub)
                        inv.clear(); inv.update(temp2_inv)
                        
                        if viable:
                            break
                
                known.clear(); known.update(temp_known)
                sub.clear(); sub.update(temp_sub)
                inv.clear(); inv.update(temp_inv)
                
                if viable:
                    final_candidates.append(c1)
            
            if len(final_candidates) == 1:
                c = final_candidates[0]
                decoded_flag.append(c)
                sw = super_words[c]
                place_superword(pos, sw)
                pos += len(sw)
                sync_mappings()
                print(f"  Resolved by deep look-ahead: {c}")
                if c == '}':
                    print(f"\nDone! Decoded {len(decoded_flag)} characters.")
                    break
            else:
                print(f"  Still ambiguous after deep look-ahead: {final_candidates}")
                break

# ── Output result ────────────────────────────────────────────────────────────
flag_str = "".join(decoded_flag)
# The encoding uppercased everything; CTF flags are typically lowercase
flag_lower = flag_str.lower()
print(f"\n{'='*60}")
print(f"FLAG (uppercase): {flag_str}")
print(f"FLAG (lowercase): {flag_lower}")
print(f"{'='*60}")

# Verify: remaining ciphertext should be accounted for (padding)
total_pt_chars = pos
total_ct_chars = N * 2
remaining = total_ct_chars - total_pt_chars
print(f"\nPlaintext chars used: {total_pt_chars}, CT chars: {total_ct_chars}, remaining: {remaining}")
if remaining > 0:
    print(f"  (Remaining {remaining} chars are likely from padding)")
