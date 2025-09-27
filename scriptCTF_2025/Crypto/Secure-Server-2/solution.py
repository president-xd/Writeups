from Crypto.Cipher import AES

# Meet in the middle for keys 3 and 4
ct = bytes.fromhex('19574ac010cc9866e733adc616065e6c019d85dd0b46e5c2190c31209fc57727')
k3 = {}
for key in range(2**16):
    cipher = AES.new(bin(key)[2:].zfill(16).encode(), mode=AES.MODE_ECB)
    # try:
    enc = cipher.encrypt(ct).hex()
    k3.update({enc:key})
    # except:
        # continue


ct2 = bytes.fromhex('0239bcea627d0ff4285a9e114b660ec0e97f65042a8ad209c35a091319541837')
for key in range(2**16):
    cipher = AES.new(bin(key)[2:].zfill(16).encode(), mode=AES.MODE_ECB)
    dec = cipher.decrypt(ct2).hex()
    if dec in k3:
        k3_final = k3[dec]
        k4_final = key
        break

# Meet in the middle for keys 1 and 2
ct3 = bytes.fromhex('4b3d1613610143db984be05ef6f37b31790ad420d28e562ad105c7992882ff34')

k1 = {}
for key in range(2**16):
    cipher = AES.new(bin(key)[2:].zfill(16).encode(), mode=AES.MODE_ECB)
    # try:
    enc = cipher.encrypt(ct3).hex()
    k1.update({enc:key})


for key in range(2**16):
    cipher = AES.new(bin(key)[2:].zfill(16).encode(), mode=AES.MODE_ECB)
    dec = cipher.decrypt(ct2).hex()
    if dec in k1:
        k1_final = k1[dec]
        k2_final = key
        break


# Decrypt message
cipher = AES.new(bin(k1_final)[2:].zfill(16).encode(), mode=AES.MODE_ECB)
cipher2 = AES.new(bin(k2_final)[2:].zfill(16).encode(), mode=AES.MODE_ECB)
secret = cipher.decrypt(cipher2.decrypt(ct))

# Print flag
k1_bytes = bytes.fromhex(hex(k1_final)[2:])
k2_bytes = bytes.fromhex(hex(k2_final)[2:])
k3_bytes = bytes.fromhex(hex(k3_final)[2:])
k4_bytes = bytes.fromhex(hex(k4_final)[2:])

print(secret+k1_bytes+k2_bytes+k3_bytes+k4_bytes)