#!/usr/bin/python3
# coding: utf-8

import socket
import struct

SO_ADDR_SIZE = 16
SO_ORIGINAL_DST = 80

def unpack_sockopt(opt):
    # https://docs.python.org/3/library/struct.html#format-characters
    # only first 8 bytes in opt is usefull, opt[8:] is 0x0000....0000
    return struct.unpack('!HHBBBB', opt[:8])

def get_sock_opt(conn):
    opt = conn.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, SO_ADDR_SIZE)
    return unpack_sockopt(opt)


addr_info = socket.getaddrinfo('127.0.0.1', 60041, 0,
                               socket.SOCK_STREAM, socket.SOL_TCP)
af, stype, proto, canname, sa = addr_info[0]
sock = socket.socket(af, stype, proto)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
sock.bind(sa)
sock.listen(4)

while True:
    try:
        conn, addr = sock.accept()
        data = conn.recv(65536)
        print(data)
    except KeyboardInterrupt:
        import sys
        sys.exit()
