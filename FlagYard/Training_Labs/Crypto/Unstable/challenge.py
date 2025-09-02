from Crypto.Util.number import *
import random

def xor(msg,key):
    return bytes([msg[i] ^ key[i % len(key)] for i in range(len(msg))])

flag = "FlagY{not_the_right_flag}"
flag = xor(flag.encode(),chr(random.randint(0,125)).encode())
pad1x = chr(random.randint(0,125)).encode()
pad2x = chr(random.randint(0,125)).encode()

def pad1(part1):
    return part1 + pad1x * (256 - len(part1) % 256)

def pad2(part2):
    return part2 + pad2x * (256 - len(part2) % 256)

def split(flag):
    return flag[0:len(flag)//2], flag[len(flag)//2:]

def Unstable(part,p,q,myprime,x):
    if x == 1:
        padpart = pad1(part)
    else:
        padpart = pad2(part)
    partlongs = bytes_to_long(part)
    padpartlongs = bytes_to_long(padpart)
    print(f"n{x} = " + str(p*q))
    ciphertext1 = (partlongs * (myprime + partlongs)) %  (p*q)
    print(f"ct{x*2-1} = {str(ciphertext1)}")
    ciphertext2 = (padpartlongs * (myprime + padpartlongs)) %  (p*q)
    print(f"ct{x*2} = {str(ciphertext2)}\n")

myprime = getPrime(128)
prime1,prime2,prime3,prime4 = 0,0,0,0
while True:
    prime1 = 3 * myprime * getPrime(256) + (2)
    if isPrime(prime1):
        break
while True:
    prime2 = 3 * myprime * getPrime(256) + 2
    if isPrime(prime2):
        break
while True:
    prime3 = 3 * myprime * getPrime(256) + 2
    if isPrime(prime3):
        break
while True:
    prime4 = 3 * myprime * getPrime(256) + 2
    if isPrime(prime4):
        break

fl,ag = split(flag)
Unstable(fl,prime1,prime2,myprime,1)
Unstable(ag,prime3,prime4,myprime,2)