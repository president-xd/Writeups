#!/usr/local/bin/python
import string
import random
import re
import os
from math import gcd
from Crypto.Util.number import getPrime, bytes_to_long

try:
    flag = open("/flag.txt", "r").read().strip()
except FileNotFoundError:
    flag = "BHFlagY{00000000000000000000000000000000}"
assert re.match(r"BHFlagY\{[0-9a-f]{32}}", flag)

def lorem_sentence():
    words = []
    for _ in range(random.randint(8, 12)):
        word = "".join(random.choices(string.ascii_letters, k=random.randint(5, 9)))
        words.append(word)
    return " ".join(words).capitalize() + "."

sentences = []
for i in range(10):
    sentences.append(lorem_sentence())
sentences[0] += f" Congratulations! The flag is {flag}."

e = 13
while True:
    p = getPrime(512)
    q = getPrime(512)
    if gcd((p-1)*(q-1), e) == 1:
        break
n = p * q

print(f"{e = }")
print(f"{n = }")
for sentence in sentences:
    print(re.sub(r"\w", "x", sentence))

for i in range(4):
    seed = int(input(f"#{i+1} seed: "))
    random.seed(seed)
    paragraph = " ".join(random.sample(sentences, k=5))
    pt = bytes_to_long(paragraph.encode())
    ct = pow(pt, e, n)
    print(f"{ct = }")
