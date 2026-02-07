"""
Solver for trigram substitution cipher challenge.

The cipher uses 3 independent alphabet shuffles (one per trigram position),
making it effectively 3 monoalphabetic ciphers. We crack it using:
  1. Known plaintext from the flag prefix "lactf" → "zjlel"
  2. Simulated annealing with English bigram scoring
"""
import re, random, math
from collections import Counter

with open("ct.txt", "r") as f:
    ct = f.read().strip()

ct_alpha = ''.join(c.lower() for c in ct if c.isalpha())
n = len(ct_alpha)

# -- Known plaintext: the full flag --
flag_ct_raw = "zjlel{heqmz_dgk_tevr_tk_vnnds_c_imcqaeyde_ug_byndu_e_jjaogy_rqqnisoqe_cwtnamd}"
flag_pt_raw = "lactf{still_too_lazy_to_write_a_plaintext_so_heres_a_random_wikipedia_article}"
flag_ct_alpha = re.sub(r'[^a-zA-Z]', '', flag_ct_raw).lower()
flag_pt_alpha = re.sub(r'[^a-zA-Z]', '', flag_pt_raw).lower()
flag_start = n - len(flag_ct_alpha)

inv = [{} for _ in range(3)]
for i in range(len(flag_ct_alpha)):
    inv[(flag_start + i) % 3][flag_ct_alpha[i]] = flag_pt_alpha[i]

for s in range(3):
    print(f"Stream {s}: {len(inv[s])} known mappings")

# -- Precompute structures for speed --
ct_arr = [ord(c) - 97 for c in ct_alpha]
stream_pos = [[], [], []]
for i in range(n):
    stream_pos[i % 3].append(i)

bg = [[0]*26 for _ in range(26)]
for pair, sc in [
    ("th",56),("he",33),("in",28),("er",27),("an",26),("re",21),("on",20),
    ("at",20),("en",19),("nd",19),("ti",18),("es",18),("or",17),("te",17),
    ("of",16),("ed",16),("is",16),("it",15),("al",15),("ar",15),("st",15),
    ("to",14),("nt",14),("ng",14),("se",14),("ha",14),("as",13),("ou",13),
    ("io",13),("le",13),("ve",13),("co",13),("me",12),("de",12),("hi",12),
    ("ri",12),("ro",12),("ic",12),("ne",12),("ea",12),("ra",12),("ce",11),
    ("li",11),("ch",11),("ll",11),("be",11),("ma",11),("si",11),("om",11),
    ("ur",10),("ca",10),("el",10),("ta",10),("la",10),("ns",10),("di",10),
    ("fo",10),("ho",10),("pe",10),("ec",10),("pr",10),("no",10),("ct",10),
    ("us",10),("ac",10),("ot",9),("il",9),("tr",9),("ly",9),("nc",9),
    ("et",9),("ut",9),("ss",9),("so",8),("rs",8),("un",8),("lo",8),
    ("wa",8),("ge",8),("ie",8),("wh",8),("ee",8),("wi",8),("em",8),
    ("ad",8),("ol",8),("rt",8),("po",8),("we",8),("na",8),("ul",8),
    ("ni",8),("ts",8),("mo",8),("ow",8),("pa",8),("im",8),("mi",8),
    ("ai",8),("sh",8),("ir",8),("su",8),("id",8),("os",8),("iv",8),
    ("ia",8),("am",8),("fi",8),("ci",8),("vi",8),("pl",8),("ig",8),
    ("tu",8),("ev",8),
]:
    bg[ord(pair[0])-97][ord(pair[1])-97] = sc

# Precompute: for each (stream, char), list of positions where that char appears
char_positions = [[[] for _ in range(26)] for _ in range(3)]
for i in range(n):
    char_positions[i % 3][ct_arr[i]].append(i)

# Precompute neighbor info: for each position, (neighbor_stream, neighbor_ct_char, is_before)
# This avoids repeated modulo and indexing in the hot loop
neighbor_before = [None] * n  # (stream, ct_char) of position i-1
neighbor_after  = [None] * n  # (stream, ct_char) of position i+1
for i in range(n):
    if i > 0:
        neighbor_before[i] = ((i-1) % 3, ct_arr[i-1])
    if i < n - 1:
        neighbor_after[i] = ((i+1) % 3, ct_arr[i+1])

def full_score(subs):
    s, prev = 0, subs[0][ct_arr[0]]
    for i in range(1, n):
        cur = subs[i % 3][ct_arr[i]]
        s += bg[prev][cur]; prev = cur
    return s

def delta_swap(subs, stream, a, b):
    d = 0
    a_old = subs[stream][a]
    b_old = subs[stream][b]
    # Process positions where char a appears (old=a_old, new=b_old)
    for pos in char_positions[stream][a]:
        nb = neighbor_before[pos]
        if nb is not None:
            prev = subs[nb[0]][nb[1]]
            d += bg[prev][b_old] - bg[prev][a_old]
        na = neighbor_after[pos]
        if na is not None:
            nxt = subs[na[0]][na[1]]
            d += bg[b_old][nxt] - bg[a_old][nxt]
    # Process positions where char b appears (old=b_old, new=a_old)
    for pos in char_positions[stream][b]:
        nb = neighbor_before[pos]
        if nb is not None:
            prev = subs[nb[0]][nb[1]]
            d += bg[prev][a_old] - bg[prev][b_old]
        na = neighbor_after[pos]
        if na is not None:
            nxt = subs[na[0]][na[1]]
            d += bg[a_old][nxt] - bg[b_old][nxt]
    return d

def init_map(s):
    freq = Counter(ct_alpha[s::3])
    ranked = [c for c,_ in freq.most_common()] + [c for c in "abcdefghijklmnopqrstuvwxyz" if c not in freq]
    m = [0]*26; used_pt = set()
    for cc, pc in inv[s].items():
        m[ord(cc)-97] = ord(pc)-97; used_pt.add(ord(pc)-97)
    rem_ct = [ord(c)-97 for c in ranked if c not in inv[s]]
    rem_pt = [ord(c)-97 for c in "etaoinshrdlcumwfgypbvkjxqz" if ord(c)-97 not in used_pt]
    for cc, pc in zip(rem_ct, rem_pt): m[cc] = pc
    return m

known_cts = [set(ord(c)-97 for c in inv[s]) for s in range(3)]
swappable = [[c for c in range(26) if c not in known_cts[s]] for s in range(3)]

best_score, best_subs = -1, None
random.seed(42)

for restart in range(5):
    subs = [init_map(s) for s in range(3)]
    for s in range(3):
        vals = [subs[s][c] for c in swappable[s]]
        random.shuffle(vals)
        for c, v in zip(swappable[s], vals): subs[s][c] = v

    cur = full_score(subs); temp = 5.0
    lens = [len(swappable[s]) for s in range(3)]
    for it in range(150000):
        s = random.randrange(3)
        L = lens[s]
        i1 = random.randrange(L); i2 = random.randrange(L - 1)
        if i2 >= i1: i2 += 1
        a, b = swappable[s][i1], swappable[s][i2]
        d = delta_swap(subs, s, a, b)
        if d > 0 or random.random() < math.exp(min(d / max(temp, 0.001), 0)):
            subs[s][a], subs[s][b] = subs[s][b], subs[s][a]; cur += d
        if it % 15000 == 0 and it: temp *= 0.6

    if cur > best_score:
        best_score, best_subs = cur, [list(s) for s in subs]
        print(f"Restart {restart}: score={cur}")

# -- Decrypt and print --
dec = ''.join(chr(best_subs[i%3][ct_arr[i]]+97) for i in range(n))
out, ai = [], 0
for c in ct:
    if c.isalpha(): out.append(dec[ai]); ai += 1
    else: out.append(c)
txt = ''.join(out)

print(txt)
print()
flag = re.search(r'\w+\{[\w]+\}', txt)
if flag:
    print(f"FLAG: {flag.group()}")
