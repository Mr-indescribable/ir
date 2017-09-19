#!/usr/bin/python3.6
# coding: utf-8

import os
import time

from ir.crypto import Cryptor
from ir.crypto.openssl import OpenSSLCryptor


def test_cryptor_reset(cn):
    c = Cryptor(cn, 'PWDDDDDDDDDDD', 'libcrypto.so.1.1',
                iv=None, reset_mode=True)
    dc = Cryptor(cn, 'PWDDDDDDDDDDD', 'libcrypto.so.1.1',
                 iv=None, reset_mode=True)
    data = b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    t0 = time.time()
    for i in range(4096):
        r = c.encrypt(data)
        r = dc.decrypt(r)
        if r != data:
            raise Exception(
                    'test_iv failed. cipher: %s, iv length: %d' % (cn, iv_len))
    t1 = time.time()
    print(t1 - t0)
    print()


def test_cryptor_reset_all_cipher():
    for cn in OpenSSLCryptor.supported_ciphers:
        print('test_cryptor_reset:\t%s' % cn)
        test_cryptor_reset(cn)


def test_iv(cn):
    data = b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    for iv_len in range(1, 10000):
        iv = os.urandom(iv_len)
        c = Cryptor(cn, 'PWDDDDDDDDDDD', 'libcrypto.so.1.1',
                    iv=iv, reset_mode=True)
        dc = Cryptor(cn, 'PWDDDDDDDDDDD', 'libcrypto.so.1.1',
                     iv=iv, reset_mode=True)
        r = c.encrypt(data)
        # print('-----------------------------')
        # print(r)
        r = dc.decrypt(r)
        if r != data:
            raise Exception(
                    'test_iv failed. cipher: %s, iv length: %d' % (cn, iv_len))
        # print(r)
        # print('-----------------------------')


def test_iv_all_cipher():
    for cn in OpenSSLCryptor.supported_ciphers:
        print('test_iv:\t%s' % cn)
        test_iv(cn)


def test_stream():
    c = Cryptor('aes-256-gcm', 'PWDDDDDDDDDDD', 'libcrypto.so.1.1',
                iv=os.urandom(32), reset_mode=True)
    st0 = b'aaaaa'
    st1 = b'bbbbbbbbbbbbb'
    t = b'1234567890-asdfg'
    a = c.encrypt(st0 + t)
    b = c.encrypt(st1 + t)
    print(a)
    print('\n--------------------\n')
    print(b)


if __name__ == '__main__':
    # test_cryptor_reset_all_cipher()
    # test_iv_all_cipher()

    test_stream()
