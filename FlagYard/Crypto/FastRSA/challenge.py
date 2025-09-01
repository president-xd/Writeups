#!/usr/local/bin/python
import os
import random
import gmpy2
from inputimeout import inputimeout 

FLAG = "FlagY{dummy_flag!}"

def encrypt(b, m):
    p = gmpy2.next_prime(2 ** b + random.randint(0, 2 ** b))
    q = gmpy2.next_prime(2 ** b + random.randint(0, 2 ** b))
    n = p * q
    print(n)
    print(m ** 3 % n)
    print((m + 1) ** 3 % n)

for i in range(1, 15):
    b = 30 * i
    m = random.randint(0, 4 ** b)
    encrypt(b, m)
    try:
        x = int(inputimeout("Enter Number : ",5))
        if x == m:
            print("============================\nKeep Going!\n============================")
            continue
        else:
            print("============================\nWrong Answer!\n============================")
            exit()
    except ValueError:
        print("============================\nNot allowed Answer!\n============================")
        exit()
    except Exception:
        exit()

print(FLAG)
