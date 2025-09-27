#!/usr/bin/env python3
import socket

HOST = "here.com"   
PORT = 00000

def solve():
    s = socket.socket()
    s.connect((HOST, PORT))

    # receive welcome line
    data = s.recv(4096).decode()
    print(data, end="")

    # send -1
    s.sendall(b"-1\n")
    data = s.recv(4096).decode()
    print(data, end="")
    remainder = int(data.strip())

    # compute secret
    secret = remainder + 1

    # send guess
    s.sendall(f"{secret}\n".encode())

    # receive flag
    data = s.recv(4096).decode()
    print(data, end="")

    s.close()

if __name__ == "__main__":
    solve()
