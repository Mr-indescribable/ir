#!/usr/bin/python3
import time
import socket


server_addr = '192.168.122.164'
server_port = 23333

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

i = 0
while True:
    i += 1
    s.sendto(str(i).encode('utf-8'), (server_addr, server_port))
    print(i)
    time.sleep(0.00005)
s.close()
