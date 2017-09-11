#!/usr/bin/python3
import time
import socket

listen_ip = '0.0.0.0'
listen_port = 23333

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((listen_ip, listen_port))

data, addr = s.recvfrom(512)

i = 0
while True:
    try:
        i += 1
        s.sendto(str(i).encode('utf-8'), addr)
        print(i)
        time.sleep(0.00005)
    except KeyboardInterrupt:
        break
