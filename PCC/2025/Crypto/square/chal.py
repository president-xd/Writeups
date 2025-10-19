#!/usr/bin/env python3
import numpy as np
import random
import string

T_Blocks = [] 

def create_secret():
    global T_Blocks
    SECRET = bytes(''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(24)), 'utf-8')
    arr = np.frombuffer(SECRET, dtype=np.uint8)
    blocks = arr.reshape(-1, 2, 2)  
    candidates = []
    for a in range(-3, 4):
        for b in range(-3, 4):
            for c in range(-3, 4):
                for d in range(-3, 4):
                    det = a*d - b*c
                    if det in (1, -1):
                        candidates.append(np.array([[a,b],[c,d]], dtype=int))

    A = random.choice(candidates)
    T_Blocks = [A @ blk for blk in blocks]


def get_blocks():
    global T_Blocks
    for i, T in enumerate(T_Blocks):
        print(f"Block {i}:")
        print(T)
        print()

def verify_solution(s):
    if s is None or len(s) != 24:
        return False
    return np.array_equal(s, np.frombuffer(bytes(T_Blocks), dtype=np.uint8).reshape(-1, 2, 2))

def get_flag():
    with open("/flag.txt", "r") as f:
        return f.read().strip()

def menu():
    print("1. Create new SECRET")
    print("2. Get transformed blocks")
    print("3. Submit Solution")
    print("4. Exit")

    while True:
        choice = input("Choice: ").strip()
        if choice == "1":
            create_secret()

            print("SECRET created")
        elif choice == "2":
            get_blocks()
        elif choice == "3":
            s = input("Enter your solution: ").encode()
            if verify_solution(s):
                print(get_flag())
            break
        else:
            print("Invalid choice")

if __name__ == "__main__":
    menu()