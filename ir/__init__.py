#!/usr/bin/python3.6
# coding: utf-8

import time

from ir.crypto import Cryptor


def test_udp_cryptor():
    c = Cryptor('aes-256-gcm', 'PWDDDDDDDDDDD', 'libcrypto.so.1.1',
                iv=None, reset_mode=True)
    dc = Cryptor('aes-256-gcm', 'PWDDDDDDDDDDD', 'libcrypto.so.1.1',
                 iv=None, reset_mode=True)
    data = b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    t0 = time.time()
    for i in range(1000):
        r = c.encrypt(data)
        dc.decrypt(r)
    t1 = time.time()
    print(t1 - t0)


if __name__ == '__main__':
    test_udp_cryptor()
