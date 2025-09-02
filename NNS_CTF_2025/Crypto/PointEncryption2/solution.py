import socket
import ssl
import re
import random

def check_left(a, b, c, d):
    if d == b:
        return c == a
    else:
        t = (c*2 + d2 - a2 - b*2) / (2 * (d - b))
        return 0 <= t <= 1

def check_right(a, b, c, d):
    if d == b:
        return c == a
    else:
        t = ((1 - c)*2 + d**2 - (1 - a)**2 - b**2) / (2 * (d - b))
        return 0 <= t <= 1

def check_bottom(a, b, c, d):
    if c == a:
        return d == b
    else:
        t = (c*2 + d2 - a2 - b*2) / (2 * (c - a))
        return 0 <= t <= 1

def check_top(a, b, c, d):
    if c == a:
        return d == b
    else:
        t = (c*2 + (1 - d2) - a2 - (1 - b)*2) / (2 * (c - a))
        return 0 <= t <= 1

def compute_bit(a, b, point):
    c, d = point
    dist_left = a
    dist_right = 1 - a
    dist_bottom = b
    dist_top = 1 - b
    min_dist = min(dist_left, dist_right, dist_bottom, dist_top)
    if dist_left == min_dist and check_left(a, b, c, d):
        return 1
    if dist_right == min_dist and check_right(a, b, c, d):
        return 1
    if dist_bottom == min_dist and check_bottom(a, b, c, d):
        return 1
    if dist_top == min_dist and check_top(a, b, c, d):
        return 1
    return 0

def read_until(sock, prompt):
    data = b''
    while prompt not in data.decode():
        chunk = sock.recv(1024)
        if not chunk:
            break
        data += chunk
    return data.decode()

def main():
    host = 'da48e5d5-5058-4219-b3bd-99b291bd4517.chall.nnsc.tf'
    port = 41337

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    ssock = context.wrap_socket(sock, server_hostname=host)

    data = read_until(ssock, "I will now allow you to encrypt anything you want, give your input as hex, write q to exit:")
    
    encrypted_flag_hex = re.search(r"Here is the encrypted flag:\n([0-9a-f]+)", data).group(1)
    points_str = re.search(r"And here are the points used to encrypt it:\n(\[.+\])", data).group(1)
    flag_points = eval(points_str)
    encrypted_flag = bytes.fromhex(encrypted_flag_hex)

    points_list = []
    bits_list = []

    plaintext_length = 100  # 100 bytes each time
    num_requests = 10

    for _ in range(num_requests):
        plaintext_hex = "00" * plaintext_length
        ssock.send(plaintext_hex.encode() + b'\n')
        response = read_until(ssock, "I will now allow you to encrypt anything you want, give your input as hex, write q to exit:")
        
        ciphertext_hex = re.search(r"Here is your message encrypted:\n([0-9a-f]+)", response).group(1)
        points_str = re.search(r"And here are the points used to encrypt it:\n(\[.+\])", response).group(1)
        points = eval(points_str)
        ciphertext = bytes.fromhex(ciphertext_hex)
        
        key_int = int.from_bytes(ciphertext, 'big')
        key_bits = bin(key_int)[2:].zfill(plaintext_length * 8)
        
        for j in range(len(points)):
            points_list.append(points[j])
            bits_list.append(int(key_bits[j]))

    if len(points_list) > 1000:
        indices = random.sample(range(len(points_list)), 1000)
        points_sub = [points_list[i] for i in indices]
        bits_sub = [bits_list[i] for i in indices]
    else:
        points_sub = points_list
        bits_sub = bits_list

    best_error = float('inf')
    best_x = (0, 0)
    step = 0.01
    for a in range(0, 101):
        a_val = a * step
        for b in range(0, 101):
            b_val = b * step
            error = 0
            for i in range(len(points_sub)):
                point = points_sub[i]
                bit_pred = compute_bit(a_val, b_val, point)
                error += abs(bit_pred - bits_sub[i])
            if error < best_error:
                best_error = error
                best_x = (a_val, b_val)

    flag_key_bits = ''
    for point in flag_points:
        bit = compute_bit(best_x[0], best_x[1], point)
        flag_key_bits += str(bit)
    flag_key_int = int(flag_key_bits, 2)
    flag_int = int.from_bytes(encrypted_flag, 'big')
    plaintext_int = flag_key_int ^ flag_int
    plaintext = plaintext_int.to_bytes((plaintext_int.bit_length() + 7) // 8, 'big')
    print(plaintext.decode())

if __name__ == '__main__':
    main()