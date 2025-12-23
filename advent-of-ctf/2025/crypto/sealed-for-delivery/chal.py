#!/usr/local/bin/python3
from Crypto.Util.number import getPrime, isPrime
from secrets import randbelow, token_urlsafe
from string import printable
import json
import time

FLAG = "csd{example_flag_1234567890}"

p = 0
while not isPrime(p // 2):
    p = getPrime(257)

g = randbelow(p)
if pow(g, p // 2, p) != 1:
    g = p - g

s = randbelow(1 << 256)

user_len = 32
user_len_bytes = 3 * user_len // 4

def mac(m, s=s):
    m = int.from_bytes(m)
    res = pow(g, m ^ s, p)
    if res > p // 2:
        res = p - res
    return int.to_bytes(res, 32)

def gen_token(username):
    info = compress(username) + int.to_bytes(int(time.time() + 300), 32 - user_len_bytes)
    return info.hex(), mac(info).hex()

def verify_token(username, info, _mac):
    try:
        info = bytes.fromhex(info)
        _mac = bytes.fromhex(_mac)
    except ValueError:
        return False
    if mac(info) != _mac:
        return False
    if compress(username) != info[:user_len_bytes]:
        return False
    if int.from_bytes(info[user_len_bytes:]) < time.time():
        return False
    if username not in login:
        return False
    return True

def compress(username):
    return int.to_bytes(sum(chars.index(char) << (6 * i) for i, char in enumerate(username.rjust(user_len, "_"))), user_len_bytes)

chars = printable[:62] + "-_"

login = {"admin": token_urlsafe()}
data = {"admin": FLAG}

# Output parameters on first connection
print(json.dumps({"p": p, "g": g}))

out = "awaiting query"
msg = {}

while True:
    msg["out"] = out
    print(json.dumps(msg))
    msg = {}
    out = ""
    try:
        query = json.loads(input())
    except json.decoder.JSONDecodeError:
        out = "invalid json"
        continue
    if "option" not in query:
        out = "no option selected"
        continue
    match query["option"]:
        case "register":
            if "username" in query and "password" in query \
            and type(query["username"]) == type(query["password"]) == str \
            and all(char in chars for char in query["username"]) \
            and query["username"][:1] in [*chars[:62]] \
            and len(query["username"]) <= user_len:
                if query["username"] not in login:
                    if "data" in query and type(query["data"]) == str:
                        login[query["username"]] = query["password"]
                        data[query["username"]] = query["data"]
                        out = "registered"
                    else:
                        out = "invalid data"
                else:
                    out = "username taken"
            else:
                out = "invalid credentials"
        case "login":
            if "username" in query and "password" in query \
            and type(query["username"]) == type(query["password"]) == str:
                if login.get(query["username"]) == query["password"]:
                    out = "logged in"
                    msg["info"], msg["mac"] = gen_token(query["username"])
                else:
                    out = "login failed"
            else:
                out = "invalid credentials"
        case "read":
            if "username" in query and "info" in query and "mac" in query \
            and type(query["username"]) == type(query["info"]) == type(query["mac"]) == str:
                if verify_token(query["username"], query["info"], query["mac"]):
                    out = "data read"
                    msg["data"] = data[query["username"]]
                else:
                    out = "invalid token"
            else:
                out = "invalid read query"
        case _:
            out = "invalid option"
