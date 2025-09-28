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

def restart(flag, n_keys):
    key_points = []
    for i in range(n_keys):
        key_point = Point(random(), random())
        encrypted_flag, flag_points = encrypt(key_point, FLAG)
        print(f"(Key {i}) Here is the encrypted flag:")
        print(encrypted_flag.hex())
        key_points.append(key_point)
    return key_points

if __name__ == "__main__":
    N_KEYS_DEFAULT = 100
    key_points = restart(FLAG, N_KEYS_DEFAULT)
    while True:
        print("I will now allow you to encrypt anything you want with any key you want, give the key you want to encrypt with and then your input as hex, write q to exit or n {number_of_keys} to get new keys:")
        inp = input()
        if inp[0] == "q":
            break
        elif inp[0] == "n":
            try:
                n_keys = int(inp[2:])
                key_points = restart(FLAG, n_keys)
                continue
            except:
                print("Invalid input")
        try:
            key, inp = inp.split(" ")
            key = int(key)
            ciphertext = bytes.fromhex(inp)
            encrypted_input, points = encrypt(key_points[key], ciphertext)
            print("Here is your message encrypted:")
            print(encrypted_input.hex())
        except:
            print("Invalid input")
