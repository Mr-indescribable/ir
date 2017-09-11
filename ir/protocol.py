#!/usr/bin/python3.6
# coding: utf-8


import time
import struct

from ir.crypto import Cryptor
from ir.tools import HashTools


__all__ = ['PacketMaker', 'PacketParser', 'IVManager']


'''Protocol of IR


TCP First Packet Format (before encrypt):
    +--------------------+-----------------------+
    |       field        |        byte(s)        |
    +--------------------+-----------------------+
    |      IV.LEN        |           1           |
    +--------------------+-----------------------+
    |        IV          |        IV.LEN         |
    +--------------------+-----------------------+
    |      MAC.LEN       |           1           |
    +--------------------+-----------------------+
    |        MAC         |        MAC.LEN        |
    +--------------------+-----------------------+
    |    DEST.AF.LEN     |           1           |
    +--------------------+-----------------------+
    |      DEST.AF       |      DEST.AF.LEN      |
    +--------------------+-----------------------+
    |       DATA         |       len(DATA)       |
    +--------------------+-----------------------+

TCP First Packet Format (encrypted):
    +--------------------+-----------------------+
    |       field        |        byte(s)        |
    +--------------------+-----------------------+
    |  encrypt(IV.LEN)   |           1           |
    +--------------------+-----------------------+
    |    encrypt(IV)     |    decrypt(IV.LEN)    |
    +--------------------+-----------------------+
    |      PAYLOAD       |     len(PAYLOAD)      |
    +--------------------+-----------------------+

TCP Comment:
    In TCP mode, local server only sends the header in first packet.
    The remote server get these necessary information from the header.
    After the remote server connected to the destination server, the
    connection transports encrypted raw data only.

    Encryption:
        PAYLOAD = encrypt(MAC.LEN + MAC + DEST.AF.LEN + DEST.AF + DATA)

        We encrypt the PAYLOAD by the cryptor instance in TCPHandler,
        and encrypt IV and IV.LEN by the shared IVCryptor

    Decryption:
        When the remote server receives first TCP packet, it should decrypt
        the first byte by the shared IVCryptor and get IV.LEN.
        Then, get IV from data and decrypt it by IVCryptor.
        Then, initialize a cryptor for the TCPHandler and decrypt the PAYLOAD.

    Authentication:
        The remote server should authenticate the first packet.
        Calculate the mac and compare it with the MAC from decrypted PAYLOAD.
        If the mac from calculation is not equal to the mac from PAYLOAD.
        Remote server should close the connection and destroy this TCPHandler.


UDP Packet Format (before encrypt):
    +--------------------+-----------------------+
    |       field        |        byte(s)        |
    +--------------------+-----------------------+
    |      MAC.LEN       |           1           |
    +--------------------+-----------------------+
    |        MAC         |        MAC.LEN        |
    +--------------------+-----------------------+
    |       SERIAL       |           4           |
    +--------------------+-----------------------+
    |        TIME        |           8           |
    +--------------------+-----------------------+
    |       IV.LEN       |           1           |
    +--------------------+-----------------------+
    |         IV         |        IV.LEN         |
    +--------------------+-----------------------+
    |    DEST.AF.LEN     |           1           |
    +--------------------+-----------------------+
    |      DEST.AF       |      DEST.AF.LEN      |
    +--------------------+-----------------------+
    |     DATA.LEN       |           4           |
    +--------------------+-----------------------+
    |       DATA         |       DATA.LEN        |
    +--------------------+-----------------------+

UDP Packet Format (encrypted):
    +--------------------+-----------------------+
    |       field        |        byte(s)        |
    +--------------------+-----------------------+
    |      PAYLOAD       |      len(PAYLOAD)     |
    +--------------------+-----------------------+

UDP Comment:
    In UDP mode, local server should add a header for every packet.

    Encryption/Decryption and IV Management:
        Three Cryptors:
            Default Cryptor:
                This cryptor is the default one that using key and iv
                from config['passwd']. It won't be removed at both side.

            New Cryptor A:
                When we need to change the iv, we should create a new
                cryptor at first. Then, we remove the 'old cryptor' if it
                can be removed. The 'old cryptor' could be 'Default Cryptor'
                or 'New cryptor A'. It should not be removed if the
                'old cryptor' is the 'Default Cryptor'.

            New Cryptor B:
                When we use A as current cryptor and we need to change the iv,
                A will be treated as 'old cryptor'. Once the iv is chenged,
                A will be removed at both side. Then, we treat B as A.

            Key:
                When the remote server reveives a packet, it need to know that
                which cryptor should be choosed.
                So, we need to provide a key for each 'New Cryptor'.
                Key format: 'saddr:sport'

            When local side lost its 'New Cryptor':
                If remote side created 'New Cryptor' already and the local
                side lost its 'New Cryptor', then they have to communicate
                with the 'Default Cryptor' and rebuild the 'New Cryptor'.
                This means the remote server have to try 2 times of
                decryption at this time.

            Demo:
                names = {
                          D: 'Default cryptor',
                          A: 'New cryptor A',
                          B: 'New cryptor B',
                        }

                comment:
                    The first row is the 'current_cryptor'.

                Normal:
                    +-----+------+     +-----+------+     +-----+------+
                    |local|remote|     |local|remote|     |local|remote|
                    +-----+------+ --> +-----+------+ --> +-----+------+
                    |  D  |  D   |     |  D  |  D   |     |  A  |  A   |
                    +-----+------+     +-----+------+     +-----+------+
                                       |  A  |  A   |     |  D  |  D   |
                                       +-----+------+     +-----+------+

                                                              |   ^
                          +------------------------------------   |
                          |                                       |
                          v                                       |
                                                                  |
                    +-----+------+     +-----+------+             |
                    |local|remote|     |local|remote|             |
                    +-----+------+ --> +-----+------+ ------------+
                    |  A  |  A   |     |  B  |  B   |
                    +-----+------+     +-----+------+
                    |  D  |  D   |     |  D  |  D   |
                    +-----+------+     +-----+------+
                    |  B  |  B   |
                    +-----+------+

                When local side lost 'New Cryptor':
                    +-----+------+     +-----+------+     +-----+------+
                    |local|remote|     |local|remote|     |local|remote|
                    +-----+------+ --> +-----+------+ --> +-----+------+
                    |  D  |  B   |     |  D  |  D   |     |  A  |  A   |
                    +-----+------+  ^  +-----+------+     +-----+------+
                    |     |  D   |  |  |  A  |  B   |     |  D  |  D   |
                    +-----+------+  |  +-----+------+     +-----+------+
                                    |  |     |  A   |
        If local   -----------------+  +-----+------+         |   ^
        sent iv                                               |   |
                                                              |   |
                          +------------------------------------   |
                          |                                       |
                          v                                       |
                                                                  |
                    +-----+------+     +-----+------+             |
                    |local|remote|     |local|remote|             |
                    +-----+------+ --> +-----+------+ ------------+
                    |  A  |  A   |     |  B  |  B   |
                    +-----+------+     +-----+------+
                    |  D  |  D   |     |  D  |  D   |
                    +-----+------+     +-----+------+
                    |  B  |  B   |
                    +-----+------+


        Change the iv:
            Local server send new iv:
                When we need to change iv, local server can fill the IV
                field in header for all packets and initialize a new cryptor
                with this iv.
                These packets should be encrypted by the old cryptor.
                Then, local server will try to decrypt packets by
                the new cryptor if it can't decrypt packets by the old cryptor.

            Remote server receive new iv:
                When remote server receive a new iv, it should initialize a new
                cryptor and reserve the old cryptor. 

            Remote server send confirmation:
                To confirm the iv change, remote server should fill the IV field
                in header with the received iv for all packet that will be send
                to local server.
                These packets should be encrypted by the new cryptor.
                Then, remote server will try to decrypt packets by
                the new cryptor if it can't decrypt packets by the old cryptor.

            Local server receive confirmation:
                When local server receive the confirmation from remote server
                and this packet is decrypted by the 'New Cryptor', it should
                stop sending the new iv to remote server.
                At this time, local server will set the IV field to empty for
                all packet and encrypt these packets by the new cryptor.

            Remote server drop old cryptor:
                When remote server successfully decrypt a packet by the new
                cryptor and get a empty IV field from this packet, Remote
                server should drop the old cryptor.
                Then, remote server set the IV field to empty for all packet.

            Local server drop old cryptor:
                When local server successfully decrypt a packet by the new
                cryptor and get a empty IV field from this packet, Local
                server should drop the old cryptor.

    Authentication:
        The remote server should authenticate every udp packet.
        Calculate the mac and compare it with the MAC from decrypted PAYLOAD.
        If the mac from calculation is not equal to the mac from PAYLOAD.
        Remote server should drop this packet.


Field Description:

    MAC.LEN:
        The length of MAC.
        Range: 0x00 - 0xFF

    MAC:
        Message Authentication Code.
        We need to authenticate the packet with this code.
        UDP packet will be dropped and TCP connection will be closed
        if the authentication is failed.

        Calculation in TCP mode:
            md5(IV.LEN + IV + DEST.AF.LEN + DEST.AF)

        Calculation in UDP mode:
            md5(SERIAL + TIME + IV.LEN + IV +\ 
                DEST.AF.LEN + DEST.AF + DATA.LEN + DATA)

    SERIAL:
        The serial number of the udp packet.
        Range: 0x00000000 - 0xFFFFFFFF
        This field is necessary in multi-transmit mod only.
        It can be fixed as 0x00000000 in normal mode.

    TIME:
        The timestamp of the udp packet.
        Range: 0x0000000000000000 - 0xFFFFFFFFFFFFFFFF

    IV.LEN:
        The length of IV.
        Range: 0x00 - 0xFF
        This field can be set to 0 if we don't need to send IV in this packet.

    IV:
        The initialization vector for ciphers.
        We can send a IV to remote server, it means that local server didn't
        use the default iv in this TCP connection. Remote server needs to use
        this given iv.  In UDP mode, server only have one cipher, so that we
        will change the shared cipher's iv if the IV is sent.

    DEST.AF.LEN:
        The length of DEST.AF.
        Range: 0x00 - 0xFF
        This field can be set to 0 if we don't need to send DEST.AF in this
        packet.

    DEST.AF:
        The IPV4 address and port of the destination.
        Range: 0x000000000000 - 0xFFFFFFFFFFFF
        First 4 bytes is the IPV4 address, last 2 bytes is the port.
        When remote UDPServer return packets to local UDPServer, this field
        should be set to empty.

    DATA.LEN:
        The length of DATA.
        Range: 0x00000000 - 0xFFFFFFFF

    DATA:
        The data from applications that we need to transport.
'''


class PacketMaker(object):

    @classmethod
    def ipv4_af_2_bytes(self, ipv4_af):
        '''('1.1.1.1', 65535) --> 0x01 0x01 0x01 0x01 0xff 0xff
        '''

        port = ipv4_af[-1]
        ip = ipv4_af[0]
        splited_ip = [int(u) for u in ip.split('.')]
        return struct.pack('BBBBH', *splited_ip, port)

    @classmethod
    def make_tcp_fpacket(cls, data, dest_af, iv, cryptor, iv_cryptor):
        '''make the first packet of tcp connection

        :param data: data from applications. Type: bytes
        :param dest_af: IPV4 address and port of dest. Struct: ('1.1.1.1', 1)
        :param iv: iv for the cipher of this connection. Type: bytes
        :param cryptor: a instance of crypto.Cryptor
                        be used to encrypt the PAYLOAD
                        different from make_udp_packet, this param is necessary
        :param iv_cryptor: be used to encrypt the IV and IV.LEN
                           different from make_udp_packet, it's necessary
        :rtype: bytes
        '''

        iv_len = struct.pack('B', len(iv))
        dest_af = cls.ipv4_af_2_bytes(dest_af)
        dest_af_len = struct.pack('B', len(dest_af))
        tmp = iv_len + iv + dest_af_len + dest_af
        mac = HashTools.md5(tmp).encode('utf-8')
        mac_len = struct.pack('B', len(mac))
        payload = mac_len + mac + dest_af_len + dest_af + data
        payload = cryptor.encrypt(payload)
        iv_len = iv_cryptor.encrypt(iv_len)
        iv = iv_cryptor.encrypt(iv)
        return iv_len + iv + payload

    @classmethod
    def make_udp_packet(cls, cryptor, data, dest_af, iv=b'', serial=0):
        '''make a udp packet

        :param data: data from applications. Type: bytes
        :param dest_af: IPV4 address and port of dest. Struct: ('1.1.1.1', 1)
        :param serial: the serial number of packet, Type: int
        :param iv: a new iv for the shared cipher. Type: bytes
        :param cryptor: a instance of crypto.Cryptor
                        be used to encrypt the final data
        :rtype: bytes
        '''

        time_ = int(time.time() * 10000000)
        serial = struct.pack('I', serial)
        time_ = struct.pack('L', time_)
        dest_af = cls.ipv4_af_2_bytes(dest_af)
        dest_af_len = struct.pack('B', len(dest_af))
        iv_len = struct.pack('B', len(iv))
        data_len = struct.pack('I', len(data))
        r_data = serial + time_ + iv_len + iv + dest_af_len +\
                    dest_af + data_len + data
        mac = HashTools.md5(r_data).encode('utf-8')
        mac_len = struct.pack('B', len(mac))
        r_data = mac_len + mac + r_data
        return cryptor.encrypt(r_data)


class PacketParser(object):

    @classmethod
    def bytes_2_ipv4_af(cls, data):
        '''0x01 0x01 0x01 0x01 0xff 0xff --> ('1.1.1.1', 65535) 
        '''

        if len(data) != 6:
            return None
        splited_af = struct.unpack('BBBBH', data)
        port = splited_af[-1]
        ip = '.'.join([str(u) for u in splited_af[:-1]])
        return (ip, port)

    @classmethod
    def auth_tcp_fpacket(cls, data):
        tmp = data['raw_iv_len'] + data['iv'] +\
                data['raw_dest_af_len'] + data['raw_dest_af']
        mac = HashTools.md5(tmp).encode('utf-8')
        if mac == data['mac']:
            return True
        return False

    @classmethod
    def parse_tcp_fpacket(cls, raw_data, iv_cryptor, config):
        '''parse a tcp packet

        :param raw_data: just data. Type: bytes
        :param iv_cryptor: a instance of crypto.Cryptor
                           be used to decrypt the IV.LEN and IV
        :param config: server_instance._config or handler_instance._config
                       I need to initialize a cryptor here, so I need the config
        :rtype: dict
        :rstruct: {
                    'valid': bool,
                    'raw_iv_len': bytes,
                    'iv_len': int,
                    'iv': bytes,
                    'mac_len': int,
                    'mac': bytes,
                    'raw_dest_af_len': bytes,
                    'dest_af_len': int,
                    'raw_dest_af': bytes,
                    'dest_af': ('0.0.0.0', 65535),
                    'data': bytes,
                    'cryptor': crypto.Cryptor(),
                  }
        '''

        res = {'valid': False}
        if len(raw_data) <= 10:
            return res

        # python3.6 will convert bytes[n] to int automatically (if it can)
        # but it won't convrt bytes[n: m]
        # I need the raw data here, so I use this expression: raw_data[n: m]
        try:
            # parse raw data and get iv
            i = 0
            raw_iv_len = iv_cryptor.decrypt(raw_data[i: i + 1])
            iv_len = struct.unpack('B', raw_iv_len)[0]
            i += 1
            iv = iv_cryptor.decrypt(raw_data[i: i + iv_len])
            i += iv_len
        except Exception:
            # a valid packet won't make any error
            # if we get an error here, it means this is a invalid packet
            return res

        cryptor = Cryptor(config.get('cipher_name'),
                          config.get('passwd'),
                          config.get('crypto_libpath'),
                          iv)
        payload = cryptor.decrypt(raw_data[i:])

        try:
            # parse payload
            i = 0
            raw_mac_len = payload[i: i + 1]
            mac_len = struct.unpack('B', raw_mac_len)[0]
            i += 1
            mac = payload[i: i + mac_len]
            i += mac_len
            raw_dest_af_len = payload[i: i + 1]
            dest_af_len = struct.unpack('B', raw_dest_af_len)[0]
            i += 1
            raw_dest_af = payload[i: i + dest_af_len]
            dest_af = cls.bytes_2_ipv4_af(raw_dest_af)
            i += dest_af_len
            data = payload[i:]
        except Exception:
            return res

        res = {
                'valid': False,
                'raw_iv_len': raw_iv_len,
                'iv_len': iv_len,
                'iv': iv,
                'mac_len': mac_len,
                'mac': mac,
                'raw_dest_af_len': raw_dest_af_len,
                'dest_af_len': dest_af_len,
                'raw_dest_af': raw_dest_af,
                'dest_af': dest_af,
                'data': data,
                'cryptor': cryptor,
                }
        if cls.auth_tcp_fpacket(res):
            res['valid'] = True
        return res

    @classmethod
    def auth_udp_packet(cls, data):
        d = data['raw_serial'] + data['raw_time'] + data['raw_iv_len'] +\
                data['iv'] + data['raw_dest_af_len'] + data['raw_dest_af'] +\
                data['raw_data_len'] + data['data']
        mac = HashTools.md5(d)
        if mac.encode('utf-8') == data['mac']:
            return True
        return False

    @classmethod
    def parse_udp_packet(cls, cryptor, raw_data):
        '''parse a udp packet

        :param raw_data: just data. Type: bytes
        :param cryptor: a instance of crypto.Cryptor
                        be used to decrypt the raw_data
        :rtype: dict
        :rstruct: {
                    'valid': bool,
                    'raw_mac_len': bytes,
                    'mac_len': int,
                    'mac': bytes,
                    'raw_serial': bytes,
                    'serial': int,
                    'raw_time': bytes,
                    'time': int,
                    'raw_iv_len': bytes,
                    'iv_len': int,
                    'iv': bytes,
                    'raw_dest_af_len': bytes,
                    'dest_af_len': int,
                    'raw_dest_af': bytes,
                    'dest_af': ('0.0.0.0', 65535),
                    'raw_data_len': bytes,
                    'data_len': int,
                    'data': bytes,
                  }
        '''

        res = {'valid': False}
        if len(raw_data) <= 10:
            return res
        raw_data = cryptor.decrypt(raw_data)

        # python3.6 will convert bytes[n] to int automatically (if it can)
        # but it won't convrt bytes[n: m]
        # I need the raw data here, so I use this expression: raw_data[n: m]
        try:
            i = 0
            raw_mac_len = raw_data[i: i + 1]
            mac_len = struct.unpack('B', raw_mac_len)[0]
            i += 1
            mac = raw_data[i: i + mac_len]
            i += mac_len
            raw_serial = raw_data[i: i + 4]
            serial = struct.unpack('I', raw_serial)
            i += 4
            raw_time = raw_data[i: i + 8]
            time_ = struct.unpack('L', raw_time)
            i += 8
            raw_iv_len = raw_data[i: i + 1]
            iv_len = struct.unpack('B', raw_iv_len)[0]
            i += 1
            iv = raw_data[i: i + iv_len]
            i += iv_len
            raw_dest_af_len = raw_data[i: i + 1]
            dest_af_len = struct.unpack('B', raw_dest_af_len)[0]
            i += 1
            raw_dest_af = raw_data[i: i + dest_af_len]
            dest_af = cls.bytes_2_ipv4_af(raw_dest_af)
            i += dest_af_len
            raw_data_len = raw_data[i: i + 4]
            data_len = struct.unpack('I', raw_data_len)[0]
            i += 4
            data = raw_data[i: i + data_len]
        except Exception:
            # a valid packet won't make any error
            # if we get an error here, it means this is a invalid packet
            return res

        res = {
                'valid': False,
                'raw_mac_len': raw_mac_len,
                'mac_len': mac_len,
                'mac': mac,
                'raw_serial': raw_serial,
                'serial': serial,
                'raw_time': raw_time,
                'time': time_,
                'raw_iv_len': raw_iv_len,
                'iv_len': iv_len,
                'iv': iv,
                'raw_dest_af_len': raw_dest_af_len,
                'dest_af_len': dest_af_len,
                'raw_dest_af': raw_dest_af,
                'dest_af': dest_af,
                'raw_data_len': raw_data_len,
                'data_len': data_len,
                'data': data,
                }
        if cls.auth_udp_packet(res):
            res['valid'] = True
        return res


class IVManager(object):

    '''For IV management of UDP communication. (we don't need it in TCP mode)
    '''

    class LocalStages:

        EXPECT_NEW_IV = 0

        # local sent a new iv to remote
        EXPECT_CONFIRM = 1

        # local got confirmation and set iv field to empty
        EXPECT_EMPTY_IV = 2

        # local got empty iv from remote, remove the old cryptor
        DONE = 3

    class RemoteStages:

        EXPECT_NEW_IV = 0

        # remote got new iv and sent confirmation to local
        EXPECT_EMPTY_IV = 1

        # remote got empty iv, set iv to empty and remove old cryptor
        DONE = 2

    class LocalCmd:

        RESET = -1
        SEND_IV = 0
        SEND_EMPTY_IV = 1
        DROP_OLD = 2
        TRANSMIT = 3

    class RemoteCmd:

        RESET = -1
        DO_CONFIRM = 0
        DROP_OLD_AND_SEND_EMPTY_IV = 1
        TRANSMIT = 2

    def __init__(self, is_local, iv=None, stage=0):
        self._stage = stage
        self._iv = iv
        self._is_local = is_local
        if self._is_local:
            self.Stages = self.LocalStages
            self.Cmd = self.LocalCmd
        else:
            self.Stages = self.RemoteStages
            self.Cmd = self.RemoteCmd

    def _local_new_stage(self, iv, decrypted_by_nc=None):
        if self._stage in (self.Stages.EXPECT_NEW_IV, self.Stages.DONE):
            if iv and iv != self._iv:
                self._iv = iv
                self._stage = self.Stages.EXPECT_CONFIRM
                return self.Cmd.SEND_IV

        if self._stage == self.Stages.EXPECT_CONFIRM:
            if not decrypted_by_nc:
                return self.Cmd.TRANSMIT
            if iv and iv == self._iv:
                self._stage = self.Stages.EXPECT_EMPTY_IV
                return self.Cmd.SEND_EMPTY_IV
            self.reset_stage()
            return self.Cmd.RESET

        if self._stage == self.Stages.EXPECT_EMPTY_IV:
            if not decrypted_by_nc:
                return self.Cmd.TRANSMIT
            if iv and iv == self._iv:
                return self.Cmd.TRANSMIT
            if not iv:
                self._stage = self.Stages.DONE
                return self.Cmd.DROP_OLD
            self.reset_stage()
            return self.Cmd.RESET

        return self.Cmd.TRANSMIT

    def _remote_new_stage(self, iv, decrypted_by_nc):
        if self._stage in (self.Stages.EXPECT_NEW_IV, self.Stages.DONE):
            if iv and iv != self._iv:
                self._iv = iv
                self._stage = self.Stages.EXPECT_EMPTY_IV 
                return self.Cmd.DO_CONFIRM

        if self._stage == self.Stages.EXPECT_EMPTY_IV:
            if not decrypted_by_nc:
                return self.Cmd.TRANSMIT
            if iv and iv == self._iv:
                return self.Cmd.TRANSMIT
            if not iv:
                self._stage = self.Stages.DONE
                return self.Cmd.DROP_OLD_AND_SEND_EMPTY_IV
            self.reset_stage()
            return self.Cmd.RESET

        return self.Cmd.TRANSMIT

    def new_stage(self, iv, decrypted_by_nc=None):
        if self._is_local:
            return self._local_new_stage(iv, decrypted_by_nc)
        else:
            return self._remote_new_stage(iv, decrypted_by_nc)

    def reset_stage(self):
        self._stage = self.Stages.EXPECT_NEW_IV

    @property
    def stage(self):
        return self._stage


def test_tcp_fpacket_make_and_parse():
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
    method = 'aes-256-gcm'
    pwd = 'aaaaaaaaaaaaaaa'
    local_ct = Cryptor(method, pwd)
    # pwd = 'aaaaaaaaaaaaabb'
    remote_ct = Cryptor(method, pwd)

    data = b'test00000'
    dest_af = ('192.168.122.1', 53)
    iv = b'aaaaaaaabbbb'
    r = PacketMaker.make_udp_packet(data, dest_af, local_ct, iv)
    print(r)
    print('-----------------')
    r = PacketParser.parse_udp_packet(r, remote_ct)
    print(r)


if __name__ == '__main__':
    test_tcp_fpacket_make_and_parse()
    test_udp_packet_make_and_parse()
