#!/usr/bin/env python3
import random
import subprocess
import time

n = 200000

nums = ''

for i in range(n):
    num = random.randint(2, n)
    nums += str(num) + ' '
    print(num, end=' ')

print()

nums += '\n'

start = time.time()

ur_output = int(input())

proc = subprocess.run(['./solve'], input=nums.encode(), stdout=subprocess.PIPE)
longest_subsequence = int(proc.stdout.decode().strip())

if ur_output == longest_subsequence:
    if time.time() - start < 10:
        print(open('flag.txt', 'r').readline())
    else:
        print("tletletletletle")
else:
    print('scriptCTF{this_is_def_the_flag_trust}')
