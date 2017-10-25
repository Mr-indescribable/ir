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


def test_tcp_fpacket_make_and_parse():
    print('test tcp fpacket...\n')
    from ir.protocol.base import PacketMaker, PacketParser

    config = {
            'cipher_name': 'aes-256-gcm',
            'passwd': 'aaaaaaaaaaaaaaa',
            'crypto_libpath': 'libcrypto.so.1.1',
            }
    iv = b'asldjfl;akjdf;lajs;ldfjk'

    local_ct = Cryptor(config['cipher_name'], config['passwd'],
                       config['crypto_libpath'], iv)
    local_iv_ct = Cryptor(config['cipher_name'], config['passwd'])
    remote_iv_ct = Cryptor(config['cipher_name'], config['passwd'])

    data = b'testing-=-=-=-=-=-=-=-'
    dest_af = ('192.168.122.1', 53)

    r = PacketMaker.make_tcp_fpacket(data, dest_af, iv, local_ct, local_iv_ct)
    print(r)
    print('--------------')
    r = PacketParser.parse_tcp_fpacket(r, remote_iv_ct, config)
    print(r)


def test_udp_packet_make_and_parse():
    print('test udp packet...\n')
    from ir.protocol.base import PacketMaker, PacketParser

    method = 'aes-256-gcm'
    pwd = 'aaaaaaaaaaaaaaa'
    local_ct = Cryptor(method, pwd)
    # pwd = 'aaaaaaaaaaaaabb'
    remote_ct = Cryptor(method, pwd)

    data = b'test00000'
    dest_af = ('192.168.122.1', 53)
    iv = b'aaaaaaaabbbb'
    r = PacketMaker.make_udp_packet(local_ct, data, dest_af, iv)
    print(r)
    print('-----------------')
    r = PacketParser.parse_udp_packet(remote_ct, r)
    print(r)


def test_tou_data_packet_make_and_parse():
    print('test tou packet...\n')
    from ir.protocol.tou import PacketMaker, PacketParser

    serial = 65536

    print('tp0-------------------')
    # type 0
    dest_af = ('192.168.1.1', 33333)
    packet = PacketMaker.make_tou_packet(serial=serial, amount=10, type_=0,
                                         dest_af=dest_af)
    res = PacketParser.parse_tou_packet(packet)
    print(packet)
    print(res)

    print('tp1-------------------')
    # type 1
    conn_status = 3
    packet = PacketMaker.make_tou_packet(serial=serial, amount=11, type_=1,
                                         conn_status=conn_status)
    res = PacketParser.parse_tou_packet(packet)
    print(packet)
    print(res)

    print('tp2-------------------')
    # type 2
    data_serial = 32767
    data = b':aaaaaaaaaaaaaaaaaaaa:'
    packet = PacketMaker.make_tou_packet(serial=serial, amount=12, type_=2,
                                         data_serial=data_serial, data=data)
    res = PacketParser.parse_tou_packet(packet)
    print(packet)
    print(res)

    print('tp3-------------------')
    # type 3
    ack_type = 1
    recvd_serial = 1023
    packet = PacketMaker.make_tou_packet(serial=serial, type_=3,
                                         ack_type=ack_type,
                                         recvd_serial=recvd_serial)
    res = PacketParser.parse_tou_packet(packet)
    print(packet)
    print(res)

    print('tp4-------------------')
    # type 4
    lost_serial = 2047
    packet = PacketMaker.make_tou_packet(serial=serial, amount=14, type_=4,
                                         lost_serial=lost_serial)
    res = PacketParser.parse_tou_packet(packet)
    print(packet)
    print(res)


if __name__ == '__main__':
    # test_cryptor_reset_all_cipher()
    # test_iv_all_cipher()
    # test_stream()

    # test_tcp_fpacket_make_and_parse()
    # test_udp_packet_make_and_parse()
    test_tou_data_packet_make_and_parse()
