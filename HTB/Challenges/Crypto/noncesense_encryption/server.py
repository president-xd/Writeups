from time import time
from Crypto.Util.number import bytes_to_long, long_to_bytes

FLAG = open('flag.txt').read()

class CustomEncryptionScheme:
    def __init__(self):
        self.generator = bytes_to_long(FLAG.encode())
        self.k = 0x13373
        self.nonce = int(time())
        self.counter = 0

    def __gen_base_key(self):
        key = self.generator % ((self.nonce + self.counter)*self.k)
        self.counter += 1
        return key

    def __gen_key(self):
        key = self.__gen_base_key()
        kh = key >> 25
        kl = key & 0x1ffffff
        tmp = []
        for __ in range(10):
            for _ in range(25):
                kh, kl = kl, kh ^ kl
            tmp.append(kh << 25 | kl)
        new_key = 0
        for i in range(10):
            new_key = (new_key << 50) | tmp[i]
        return new_key

    def encrypt(self, msg) -> bytes:
        if type(msg) is str:
            msg = bytes_to_long(msg.encode())
        if type(msg) is bytes:
            msg = bytes_to_long(msg)

        key = self.__gen_key()
        return long_to_bytes(msg ^ key)

def main():
    ces = CustomEncryptionScheme()

    banner = """
--------------------------------
I feel like I'm a master of OTPs now
--------------------------------
This key generation scheme allows me to just use a single key to encrypt all my messages!
--------------------------------
Please go ahead and test it!"""


    print(banner)

    while True:
        message = input("Enter a message to encrypt (or type 'exit' to quit): ")
        
        if message.lower() == 'exit':
            break

        encrypted_message = ces.encrypt(message)
        print(f"Encrypted Message: {encrypted_message.hex()}")

if __name__ == '__main__':
    assert FLAG.startswith('HTB{') and FLAG.endswith('}')
    main()
