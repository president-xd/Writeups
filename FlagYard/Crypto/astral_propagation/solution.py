import socket
import time

def xor_bytes(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

MESSAGE = b'propagating cipher block chaining'
padded = MESSAGE + bytes([15] * 15)
M1 = padded[0:16]
M2 = padded[16:32]
M3 = padded[32:48]

class Oracle:
    def __init__(self):
        self.host = '52.50.32.75'
        self.port = 32757
        self.s = None
        
    def connect(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((self.host, self.port))
        self.s.recv(1024)
        
    def send(self, ct_bytes):
        ct_hex = ct_bytes.hex()
        self.s.send(ct_hex.encode() + b'\n')
        response = self.s.recv(1024).decode().strip()
        return response
        
    def close(self):
        self.s.close()

def is_padding_valid(response):
    return 'failed to decrypt' not in response

def find_I(C, oracle):
    I = bytearray(16)
    for k in range(1, 17):
        i = 16 - k
        IV_prime = bytearray(16)
        for j in range(i+1, 16):
            IV_prime[j] = I[j] ^ k
        found = False
        for candidate in range(256):
            IV_prime[i] = candidate
            ct = bytes(IV_prime) + C
            response = oracle.send(ct)
            if is_padding_valid(response):
                I[i] = candidate ^ k
                found = True
                break
        if not found:
            raise Exception(f"Failed to find byte at index {i}")
    return bytes(I)

def main():
    oracle = Oracle()
    oracle.connect()
    
    C3 = b'\x00' * 16
    print("Finding I3 for C3...")
    I3 = find_I(C3, oracle)
    print(f"I3 = {I3.hex()}")
    
    C2 = xor_bytes(xor_bytes(M2, M3), I3)
    print(f"C2 = {C2.hex()}")
    
    print("Finding I2 for C2...")
    I2 = find_I(C2, oracle)
    print(f"I2 = {I2.hex()}")
    
    C1 = xor_bytes(xor_bytes(M2, M1), I2)
    print(f"C1 = {C1.hex()}")
    
    print("Finding I1 for C1...")
    I1 = find_I(C1, oracle)
    print(f"I1 = {I1.hex()}")
    
    IV = xor_bytes(I1, M1)
    print(f"IV = {IV.hex()}")
    
    ct_full = IV + C1 + C2 + C3
    print(f"Full ciphertext: {ct_full.hex()}")
    
    response = oracle.send(ct_full)
    print(response)
    
    oracle.close()

if __name__ == '__main__':
    main()