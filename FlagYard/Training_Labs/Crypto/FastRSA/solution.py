import socket

def readline(sock):
    data = b''
    while True:
        byte = sock.recv(1)
        if not byte:
            break
        data += byte
        if byte == b'\n':
            break
    return data.decode().strip()

host = "52.50.32.75"
port = 32757

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))

n_line = readline(s)
c1_line = readline(s)
c2_line = readline(s)
prompt = s.recv(15)

n = int(n_line)
c1 = int(c1_line)
c2 = int(c2_line)

for round in range(14):
    A = (2 + c2 - c1) % n
    B = (c2 + 2*c1 - 1) % n
    inv_A = pow(A, -1, n)
    m = (B * inv_A) % n
    
    s.sendall(str(m).encode() + b'\n')
    
    if round == 13:
        break
        
    line1 = readline(s)
    line2 = readline(s)
    line3 = readline(s)
    
    n_line = readline(s)
    c1_line = readline(s)
    c2_line = readline(s)
    prompt = s.recv(15)
    
    n = int(n_line)
    c1 = int(c1_line)
    c2 = int(c2_line)
    
response = b''
while True:
    data = s.recv(1024)
    if not data:
        break
    response += data
    
print(response.decode())
s.close()