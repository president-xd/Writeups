#!/usr/bin/env python3
import socket
import base64
import struct
import sys
import time

# --- GF(2^128) Arithmetic for GCM ---

class GF128:
    def __init__(self):
        self.R = 0xE1000000000000000000000000000000
    
    def add(self, a, b):
        return a ^ b
    
    def mul(self, x, y):
        z = 0
        v = x
        for i in range(128):
            if (y >> (127 - i)) & 1:
                z ^= v
            if v & 1:
                v = (v >> 1) ^ self.R
            else:
                v >>= 1
        return z

    def pow(self, a, n):
        res = 1 << 127
        b = a
        while n > 0:
            if n & 1:
                res = self.mul(res, b)
            b = self.mul(b, b)
            n >>= 1
        return res

    def inv(self, a):
        return self.pow(a, (1 << 128) - 2)
    
    def sqrt(self, a):
        return self.pow(a, 1 << 127)

gf = GF128()

def bytes_to_int(b):
    return int.from_bytes(b, 'big')

def int_to_bytes(i):
    return i.to_bytes(16, 'big')

def ghash(h, aad, ciphertext):
    len_aad = len(aad)
    len_ct = len(ciphertext)
    
    if len_aad % 16:
        aad += b'\x00' * (16 - len_aad % 16)
    if len_ct % 16:
        ciphertext += b'\x00' * (16 - len_ct % 16)
        
    blocks = []
    for i in range(0, len(aad), 16):
        blocks.append(bytes_to_int(aad[i:i+16]))
    for i in range(0, len(ciphertext), 16):
        blocks.append(bytes_to_int(ciphertext[i:i+16]))
    
    len_block = (len_aad * 8) << 64 | (len_ct * 8)
    blocks.append(len_block)
    
    y = 0
    for b in blocks:
        y = gf.add(y, b)
        y = gf.mul(y, h)
    return y

# --- Connection Handler with Buffering ---

class Connection:
    def __init__(self, host='192.168.0.154', port=5000):
        print(f"[DEBUG] Connecting to {host}:{port}...", flush=True)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.settimeout(5.0)
        self.s.connect((host, port))
        self.buf = b''
        print("[DEBUG] Connected", flush=True)

    def recv_until(self, marker):
        while marker not in self.buf:
            try:
                chunk = self.s.recv(4096)
                if not chunk: break
                self.buf += chunk
            except socket.timeout:
                print("[DEBUG] Timeout in recv_until", flush=True)
                break
        
        if marker in self.buf:
            idx = self.buf.find(marker)
            # Consume up to end of marker
            ret = self.buf[:idx+len(marker)]
            self.buf = self.buf[idx+len(marker):]
            return ret
        return b''

    def recv_line(self):
        while b'\n' not in self.buf:
            try:
                chunk = self.s.recv(4096)
                if not chunk: break
                self.buf += chunk
            except socket.timeout:
                print("[DEBUG] Timeout in recv_line", flush=True)
                break
        
        if b'\n' in self.buf:
            idx = self.buf.find(b'\n')
            line = self.buf[:idx]
            self.buf = self.buf[idx+1:]
            return line
        return b''
        
    def send_line(self, msg):
        self.s.sendall(msg + b'\n')
        
    def close(self):
        self.s.close()

# --- Exploit Logic ---

def get_tag(conn, prompt, payload):
    conn.recv_until(prompt)
    conn.send_line(payload)
    conn.recv_until(b':  ')
    line = conn.recv_line()
    return base64.b64decode(line.strip())

def oracle_query(conn, length, aad):
    conn.send_line(f"{length}".encode())
    conn.recv_until(b'aad: ')
    conn.send_line(base64.b64encode(aad))
    res = conn.recv_line()
    return b'True' in res

def solve():
    print("[*] Starting Advanced Oracle Attack (Single Session)...")
    conn = Connection()
    
    try:
        # 1. Get Flag Info
        conn.recv_until(b'flag ciphertext:  ')
        line = conn.recv_line()
        flag_ct = base64.b64decode(line.strip())
        
        conn.recv_until(b'flag tag:  ')
        line = conn.recv_line()
        flag_tag = base64.b64decode(line.strip())
        flag_tag_int = bytes_to_int(flag_tag)
        
        print(f"[+] Flag CT: {flag_ct.hex()}")
        
        # 2. Send Text1 and Text2
        # Text1: 32 bytes zeros
        p1 = b'\x00' * 32
        print("[*] Sending Text1...")
        tag1 = get_tag(conn, b'your_text1:', p1)
        tag1_int = bytes_to_int(tag1)
        
        # Text2: 16 bytes zeros + 1 byte 1 + 15 bytes zeros
        p2 = b'\x00' * 16 + b'\x01' + b'\x00' * 15
        print("[*] Sending Text2...")
        tag2 = get_tag(conn, b'your_text2:', p2)
        tag2_int = bytes_to_int(tag2)
        
        # 3. Recover H
        print("[*] Recovering H...")
        diff_tag = tag1_int ^ tag2_int
        diff_block2 = bytes_to_int(p1[16:]) ^ bytes_to_int(p2[16:])
        inv_diff = gf.inv(diff_block2)
        h2 = gf.mul(diff_tag, inv_diff)
        h = gf.sqrt(h2)
        print(f"[+] H: {hex(h)}")
        
        # 4. Recover AuthMask
        print("[*] Recovering AuthMask...")
        ghash_flag = ghash(h, b'', flag_ct)
        auth_mask = flag_tag_int ^ ghash_flag
        print(f"[+] AuthMask: {hex(auth_mask)}")
        
        # 5. Recover Keystream using Oracle
        print("[*] Recovering Keystream...")
        c2_recovered = bytearray()
        target_tag = tag2_int
        
        # We are now in the Oracle loop
        # We need to recover 32 bytes
        
        for i in range(32):
            target_hash = target_tag ^ auth_mask
            
            found = False
            for g in range(256):
                current_c = c2_recovered + bytes([g])
                
                # Construct GHASH polynomial terms
                len_c = len(current_c)
                len_aad = 16
                
                # C blocks
                c_blocks = []
                temp_c = current_c + b'\x00' * ((16 - len_c % 16) % 16)
                for k in range(0, len(temp_c), 16):
                    c_blocks.append(bytes_to_int(temp_c[k:k+16]))
                
                len_block = (len_aad * 8) << 64 | (len_c * 8)
                
                m = len(c_blocks)
                
                fixed_y = 0
                power = m + 1
                for b in c_blocks:
                    term = gf.mul(b, gf.pow(h, power))
                    fixed_y = gf.add(fixed_y, term)
                    power -= 1
                
                term = gf.mul(len_block, h)
                fixed_y = gf.add(fixed_y, term)
                
                target_val = target_hash ^ fixed_y
                inv_h_pow = gf.inv(gf.pow(h, m + 2))
                a_val = gf.mul(target_val, inv_h_pow)
                
                aad_bytes = int_to_bytes(a_val)
                
                if oracle_query(conn, i + 1, aad_bytes):
                    c2_recovered.append(g)
                    print(f"\r[+] Recovered byte {i}: {hex(g)}", end='', flush=True)
                    found = True
                    break
            
            if not found:
                print(f"\n[!] Failed to recover byte {i}")
                break
        
        print(f"\n[+] C2 Recovered: {c2_recovered.hex()}")
        
        # Decrypt Flag
        k = bytearray()
        for i in range(len(c2_recovered)):
            k.append(c2_recovered[i] ^ p2[i])
        
        flag = bytearray()
        for i in range(len(flag_ct)):
            if i < len(k):
                flag.append(flag_ct[i] ^ k[i])
                
        print(f"\n[+] FLAG: {flag.decode(errors='ignore')}")
        
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        conn.close()

if __name__ == '__main__':
    solve()
