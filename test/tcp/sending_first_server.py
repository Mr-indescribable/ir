#!/usr/bin/python3.6
#coding: utf-8

import socket
from datetime import datetime


def init_socket(listen_addr='0.0.0.0', listen_port=2333, so_backlog=1024):
    addr_info = socket.getaddrinfo(listen_addr, listen_port, 0,
                                   socket.SOCK_STREAM, socket.SOL_TCP)
    af, stype, proto, canname, sa = addr_info[0]
    sock = socket.socket(af, stype, proto)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(sa)
    sock.listen(so_backlog)
    return sock


data_2_send = b''.join([b'A' for _ in range(1000)])
sock = init_socket()
while True:
    try:
        conn, addr = sock.accept()
        conn.sendall(data_2_send)
        print('--------------------------------')
        print(datetime.now())
        print('sent data to %s:%d' % addr)
        print('--------------------------------')
        conn.close()
    except KeyboardInterrupt:
        break
