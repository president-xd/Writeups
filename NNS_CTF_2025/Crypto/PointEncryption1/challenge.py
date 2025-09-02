from custom_geometry import are_equidistant_to_point_on_closest_line, Point
from Crypto.Util.number import bytes_to_long, long_to_bytes
from random import random
import os

FLAG = os.getenv("FLAG", "try again, but in production!").encode()

def encrypt(point : Point, plaintext : bytes) -> bytes:
    key = ""
    points = []
    for _ in range(len(plaintext)*8):
        random_point = Point(random(), random())
        points.append(random_point)
        key += str(are_equidistant_to_point_on_closest_line(point, random_point)*1)
    key = int(key, 2)
    return long_to_bytes(key^bytes_to_long(plaintext)), points

if __name__ == "__main__":
    key_point = Point(random(), random())
    encrypted_flag, flag_points = encrypt(key_point, FLAG)
    print("Welcome to my new encryption service!")
    print("Here is the encrypted flag:")
    print(encrypted_flag.hex())
    print("And here are the points used to encrypt it:")
    print([(p.x, p.y) for p in flag_points])
    while True:
        print("I will now allow you to encrypt anything you want, give your input as hex, write q to exit:")
        inp = input()
        if inp[0] == "q":
            break
        try:
            ciphertext = bytes.fromhex(inp)
            encrypted_input, points = encrypt(key_point, ciphertext)
            print("Here is your message encrypted:")
            print(encrypted_input.hex())
            print("And here are the points used to encrypt it:")
            print([(p.x, p.y) for p in points])
        except:
            print("Invalid input")
