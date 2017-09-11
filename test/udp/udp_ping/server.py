#!/usr/bin/python3
import socket

listen_ip = '0.0.0.0'
listen_port = 60051

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((listen_ip, listen_port))

while True:
    try:
        data, addr = s.recvfrom(512)
        s.sendto(data, addr)
    except KeyboardInterrupt:
        break
