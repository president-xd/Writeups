#!/usr/bin/env python3
#
# BlackHat MEA CTF 2025 Qualifiers :: Hatagawa II
#
#

# Documentation imports
from __future__ import annotations
from typing import Tuple, List, Dict, NewType, Union

# Native imports
from secrets import randbelow
import os

# External dependencies
# None

# Flag import
FLAG = os.environ.get('DYN_FLAG', 'BHFlagY{' + b'D3BUGG1NG_1S_FUN'.hex() + '}')
if isinstance(FLAG, str):
    FLAG = FLAG.encode()
    FFMT = (FLAG[:FLAG.index(b'{') + 1], b'}')


# Helper functions
# None


# Challenge classes
class Kawa:
    """ 川 """
    def __init__(self, par: Tuple[int], seed: int) -> None:
        self.a, self.c, self.m = par
        self.x = seed

    def Get(self) -> bytes:
        """ Generates and outputs the next internal state as bytes. """
        self.x = (self.a * self.x + self.c) & self.m
        return self.x.to_bytes(-(-self.m.bit_length() // 8), 'big')
    
class Hata:
    """ 旗 """
    def __init__(self, entropy: object) -> None:
        self.entropy = entropy

    def Strip(self, msg: bytes, fmt: Tuple[bytes, bytes]) -> bytes:
        """ Strips a message from given bytestring formatting. """
        return bytes.fromhex(msg.replace(fmt[0], b'').replace(fmt[1], b'').decode())
    
    def Unstrip(self, cip: str, fmt: Tuple[bytes, bytes]) -> str:
        """ Add given string formatting to a ciphertext. """
        return fmt[0].decode() + cip + fmt[1].decode()

    def Encrypt(self, msg: bytes, fmt: Tuple[bytes, bytes]) -> bytes:
        """ Encrypts a message (except its formatting) using a one-time pad generated from entropy source. """
        msg = self.Strip(msg, fmt)
        otp = b''
        while len(otp) <= len(msg):
            otp += self.entropy.Get()
        cip = bytes([x ^ y for x,y in zip(msg, otp)])
        return self.Unstrip(cip.hex(), fmt)


# Main loop
if __name__ == "__main__":

    # Challenge parameters
    MOD = 2**64 - 1
    MUL = (randbelow(MOD >> 3) << 3) | 5
    ADD = randbelow(MOD) | 1


    # Challenge setup
    hatagawa = Hata(Kawa((MUL, ADD, MOD), randbelow(MOD)))

    RIVER = r"""|
|  ////\\\,,\///,,,,,\,/,\\,//////,\,,\\\,,\\\/,,,\,,//,\\\,
|   ~ ~~~~ ~~ ~~~~~~~ ~ ~~ ~~~~~~ ~  ~~~    ~~~ ~~~ ~~   ~~
|    ~~~~~~~  ~~~~~~   ~~~ ~ ~~~~~ ~~ ~~~~~~~ ~ ~~ ~~~~~
|   ~~~     {}      ~
|    ~~~  ~   ~~~~~  ~~~~ ~ ~~~~   ~~~~~ ~~~~   ~~~ ~ ~~~~~
|   ~~~ ~  ~~~~~  ~  ~~  ~  ~~~~ ~~~ ~~   ~~ ~~~~~~~ ~ ~~
|  \\\\\'''\\'////'//'\''\\\/'''\''//'\\\''\///''''\'/'\\'//"""
    print(RIVER.format(' '*17 + '旗    川' + ' '*16))


    # Main loop
    userOptions = ['Stay a while...']
    TUI = "|\n|  Menu:\n|    " + "\n|    ".join('[' + i[0] + ']' + i[1:] for i in userOptions) + "\n|    [W]alk away\n|"

    while True:
        try:

            print(TUI)
            choice = input('|  > ').lower()

            # [W]alk away
            if choice == 'w':
                print("|\n|  [~] You turn your back to the river...\n|")
                break

            # [S]tay a while...
            elif choice == 's':

                print("|\n|  [~] Look! A flag..? For FREE?!")
                print(RIVER.format(hatagawa.Encrypt(FLAG, FFMT)))

            else:
                print("|\n|  [!] Invalid choice.")

        except KeyboardInterrupt:
            print("\n|\n|  [~] Goodbye ~ !\n|")
            break

        except Exception as e:
            print('|\n|  [!] {}'.format(e))% 
