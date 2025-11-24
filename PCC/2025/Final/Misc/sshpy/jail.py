#!/usr/bin/env python3

import re
import os
import chardet

try:
    code = input("$ ")
except KeyboardInterrupt:
    print("Bro chickened out :(")
except Exception as E:
    print(f"An error occurred: {E}")
    os._exit(1)

if chardet.detect(code.encode('utf-8'))['encoding'] != "ascii":
    print("this trick won't work here :(")
    os._exit(1)

blacklist = (
    "import", "os", "subprocess", "sys",
    "sh", "main", "re", "class", "open",
    "print", "breakpoint", "pdb", "raise",
    "globals", "builtins"
) # some are > 6 cuz why not ;)

if not re.fullmatch(r"[A-Za-z0-9()_]{1,6}", code):
    print("(: you need to try harder :)")
    os._exit(1)

if any(bc in code for bc in blacklist):
    print("sometimes, the blacklist is the hardest part :(")
    os._exit(1)

try:
    eval(code)
except Exception as E:
    print(f"An error occurred: {E}")