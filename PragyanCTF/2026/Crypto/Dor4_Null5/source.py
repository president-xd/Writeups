import os
from dotenv import load_dotenv
load_dotenv()
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto.Protocol.KDF import HKDF

flag = os.environ.get("FLAG", "p_ctf{HIDDEN}")
BANNER = r"""                                                              
                                                                        
        ----------- dora - nulls - pctf -2026 --------------
"""
backpack = {
    "Administrator": "****************************************************************"
}

def show_map():
    print(BANNER)
    print("\n1. login")
    print("2. register")
    print("3. exit")
    return int(input("choose "))

def explore():

    challenge_hex = input("challenge (hex): ").strip()
    challenge = bytes.fromhex(challenge_hex)
    
    if len(challenge) != 8:
        print("invalid challenge length")
        return
    
    friend_name = input("username: ").strip()
    
    if not (6 < len(friend_name) < 20):
        print("invalid username length")
        return
    
    if friend_name not in backpack:
        print(f"user {friend_name} not found")
        return
    
    explorer_secret = backpack[friend_name].encode()
    
    server_token = os.urandom(8)
    print(f"server challenge: {server_token.hex()}")
    
    response_hex = input("response (hex): ").strip()
    response = bytes.fromhex(response_hex)
    
    if len(response) != 8:
        print("invalid response length")
        return
    
    navigation_key = HKDF(
        master=explorer_secret,
        key_len=16,
        salt=challenge + server_token,
        hashmod=SHA256
    )
    
    expected_path = compute_path(navigation_key, challenge)
    
    if verify_credential(navigation_key, expected_path, response):
        print(f"authentication successful: {friend_name}")
        if friend_name == "Administrator":
            print(f"flag: {flag}")
    else:
        print("authentication failed")

def add_friend():
    friend_name = input("username: ").strip()
    
    if not (6 < len(friend_name) < 20):
        print("invalid username length")
        return
    
    if friend_name in backpack:
        print("username already exists")
        return
    
    discovery_code = input("password hash (64 chars): ").strip()
    
    if len(discovery_code) != 64:
        print("invalid hash length")
        return
    
    backpack[friend_name] = discovery_code
    print("registration successful")

def compute_path(navigation_key, challenge):
    state = bytearray(16) + bytearray(challenge)
    tracker = AES.new(navigation_key, AES.MODE_ECB)
    
    for step in range(8):
        scan = tracker.encrypt(state[step:step + 16])
        state[16 + step] ^= scan[0]
    
    return bytes(state[-8:])

def verify_credential(session_key, expected, provided):
   
    h = HMAC.new(session_key, expected, SHA256)
    mask = h.digest()[:8]
    
    checksum = 0
    for i in range(8):
        checksum ^= expected[i] ^ provided[i] ^ mask[i]
    
    return checksum == 0

def main():
    for _ in range(0x1337):
        selection = show_map()
        if selection == 1:
            explore()
        elif selection == 2:
            add_friend()
        else:
            print("session terminated")
            return

if __name__ == "__main__":
    main()