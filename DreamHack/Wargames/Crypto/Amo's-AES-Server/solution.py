#!/usr/bin/env python3
"""
Socket-based solution for reversed CBC AES challenge

Attack summary:
1. The encrypt/decrypt functions are swapped (encrypt does CBC_decrypt, decrypt does CBC_encrypt)
2. flag_enc = CBC_decrypt(padded_flag), so we need CBC_encrypt(flag_enc) to recover the flag
3. The isvalid() check blocks decrypt() if input contains any flag_enc block
4. We use the encrypt oracle (no restrictions) to recover IV
5. Then we use a 2-block trick with decrypt to compute CBC_encrypt block by block
"""

import socket
import sys

BLOCK_SIZE = 16

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def split_blocks(data):
    return [data[i:i+BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]

class Connection:
    def __init__(self, host, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10)  # 10 second timeout
        print(f"[*] Attempting connection to {host}:{port}...")
        self.sock.connect((host, port))
        print(f"[+] Connected!")
        self.buffer = b''
    
    def recv_until(self, delim):
        if isinstance(delim, str):
            delim = delim.encode()
        while delim not in self.buffer:
            try:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                self.buffer += chunk
            except socket.timeout:
                print(f"[!] Timeout waiting for: {delim}")
                break
        idx = self.buffer.find(delim)
        if idx != -1:
            result = self.buffer[:idx + len(delim)]
            self.buffer = self.buffer[idx + len(delim):]
            return result
        return self.buffer
    
    def recv_line(self):
        return self.recv_until(b'\n')
    
    def send(self, data):
        if isinstance(data, str):
            data = data.encode()
        self.sock.sendall(data)
    
    def sendline(self, data):
        if isinstance(data, str):
            data = data.encode()
        self.sock.sendall(data + b'\n')
    
    def close(self):
        self.sock.close()


def solve(conn):
    # Wait for menu
    conn.recv_until(b"Welcome to dream's AES server")
    
    # Step 1: Get the encrypted flag
    conn.recv_until(b'Get Flag]\n')
    conn.sendline(b'3')
    conn.recv_until(b'flag = ')
    flag_enc = bytes.fromhex(conn.recv_line().strip().decode())
    flag_blocks = split_blocks(flag_enc)
    print(f"[*] Got flag_enc: {flag_enc.hex()}")
    print(f"[*] Number of blocks: {len(flag_blocks)}")
    
    # Step 2: Recover IV using encrypt oracle
    # encrypt(X || X) gives us:
    #   P[0] = AES_dec(X) ⊕ IV
    #   P[1] = AES_dec(X) ⊕ X
    # Therefore: IV = P[0] ⊕ P[1] ⊕ X
    
    test_block = b'\x00' * BLOCK_SIZE
    conn.recv_until(b'Get Flag]\n')
    conn.sendline(b'1')
    conn.recv_until(b'hex): ')
    conn.sendline((test_block * 2).hex().encode())
    result = bytes.fromhex(conn.recv_line().strip().decode())
    P0, P1 = result[:BLOCK_SIZE], result[BLOCK_SIZE:BLOCK_SIZE*2]
    IV = xor(xor(P0, P1), test_block)
    print(f"[+] Recovered IV: {IV.hex()}")
    
    # Step 3: Compute CBC_encrypt(flag_enc) block by block
    # We need: result[i] = AES_enc(flag_enc[i] ⊕ result[i-1]), result[-1] = IV
    #
    # Using decrypt oracle with 2 blocks (dummy || X):
    #   Out[0] = AES_enc(dummy ⊕ IV)
    #   Out[1] = AES_enc(X ⊕ Out[0])
    #
    # To get AES_enc(target), we set X = target ⊕ Out[0]
    # So Out[1] = AES_enc(target ⊕ Out[0] ⊕ Out[0]) = AES_enc(target)
    
    def find_safe_dummy():
        """Find a block that's not in flag_enc"""
        for i in range(256):
            candidate = bytes([i]) * BLOCK_SIZE
            if candidate not in flag_enc:
                return candidate
        # Try random if needed
        import os
        for _ in range(100):
            candidate = os.urandom(BLOCK_SIZE)
            if candidate not in flag_enc:
                return candidate
        raise Exception("Could not find safe dummy block")
    
    dummy = find_safe_dummy()
    print(f"[*] Using dummy block: {dummy.hex()}")
    
    # Get C_dummy = AES_enc(dummy ⊕ IV)
    conn.recv_until(b'Get Flag]\n')
    conn.sendline(b'2')
    conn.recv_until(b'hex): ')
    conn.sendline(dummy.hex().encode())
    resp = conn.recv_line().strip().decode()
    if 'Nope' in resp:
        print("[-] Dummy block rejected - shouldn't happen!")
        return None
    C_dummy = bytes.fromhex(resp)[:BLOCK_SIZE]
    print(f"[*] C_dummy = AES_enc(dummy ⊕ IV): {C_dummy.hex()}")
    
    # Now compute each block of CBC_encrypt(flag_enc)
    prev = IV  # Chaining starts with IV
    flag_plaintext = b''
    
    for i, block in enumerate(flag_blocks):
        target = xor(block, prev)  # We want AES_enc(target)
        
        # X such that AES_enc(X ⊕ C_dummy) = AES_enc(target)
        # => X ⊕ C_dummy = target
        # => X = target ⊕ C_dummy
        X = xor(target, C_dummy)
        
        # Check if X is in flag_enc (would be rejected)
        if X in flag_enc:
            print(f"[!] Block {i}: X collides with flag_enc, trying alternative dummy")
            # Try with a different dummy
            for alt in range(256):
                alt_dummy = bytes([alt]) * BLOCK_SIZE
                if alt_dummy in flag_enc:
                    continue
                    
                # Get new C_dummy for this alternative
                conn.recv_until(b'Get Flag]\n')
                conn.sendline(b'2')
                conn.recv_until(b'hex): ')
                conn.sendline(alt_dummy.hex().encode())
                alt_resp = conn.recv_line().strip().decode()
                if 'Nope' in alt_resp:
                    continue
                alt_C_dummy = bytes.fromhex(alt_resp)[:BLOCK_SIZE]
                
                X = xor(target, alt_C_dummy)
                if X not in flag_enc:
                    dummy = alt_dummy
                    C_dummy = alt_C_dummy
                    break
            else:
                print(f"[-] Block {i}: Could not find valid X")
                return None
        
        # Send decrypt(dummy || X)
        payload = dummy + X
        conn.recv_until(b'Get Flag]\n')
        conn.sendline(b'2')
        conn.recv_until(b'hex): ')
        conn.sendline(payload.hex().encode())
        
        resp = conn.recv_line().strip().decode()
        if 'Nope' in resp:
            print(f"[-] Block {i}: payload rejected by isvalid")
            print(f"    dummy: {dummy.hex()}, X: {X.hex()}")
            return None
        
        result = bytes.fromhex(resp)
        # Second block of output is AES_enc(X ⊕ C_dummy) = AES_enc(target)
        new_block = result[BLOCK_SIZE:BLOCK_SIZE*2]
        
        print(f"[*] Block {i}: {new_block}")
        flag_plaintext += new_block
        prev = new_block  # Update chaining value
    
    # Remove PKCS7 padding
    try:
        pad_len = flag_plaintext[-1]
        if pad_len <= BLOCK_SIZE and all(b == pad_len for b in flag_plaintext[-pad_len:]):
            flag_plaintext = flag_plaintext[:-pad_len]
    except:
        pass
    
    return flag_plaintext


def main():
    if len(sys.argv) < 3:
        print(f"Usage: python {sys.argv[0]} <host> <port>")
        print(f"Example: python {sys.argv[0]} localhost 1337")
        sys.exit(1)
    
    host = sys.argv[1]
    port = int(sys.argv[2])
    
    print(f"[*] Connecting to {host}:{port}")
    conn = Connection(host, port)
    
    try:
        flag = solve(conn)
        
        if flag:
            print(f"\n[+] FLAG: {flag.decode()}")
        else:
            print("\n[-] Failed to recover flag")
    finally:
        conn.close()


if __name__ == '__main__':
    main()
