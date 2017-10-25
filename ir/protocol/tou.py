#!/usr/bin/python3.6
#coding: utf-8

import sched
import select
import struct
import random
from threading import Thread, Event

from ir.protocol.base import AfConverter


__all__ = ['PacketMaker', 'PacketParser']



'''IR TCP Over UDP

Overview:
    +--------+      +--------+      +---------+      +--------+
    |        | ---> | local  | ---> |         | ---> | local  |
    |  app   |      |  TCP   |      | adapter |      |  UDP   |
    |        | <--- | server | <--- |         | <--- | server |
    +--------+      +--------+      +---------+      +--------+
                                                       ^    |
                                                       |    |
                                                       |    V
    +--------+      +--------+      +---------+      +--------+
    |  dest  | ---> | remote | ---> |         | ---> | remote |
    |        |      |  TCP   |      | adapter |      |  UDP   |
    | server | <--- | server | <--- |         | <--- | server |
    +--------+      +--------+      +---------+      +--------+

Description:
    We use the adapter to transform the data between TCP stream and UDP packets.
    The adapter also needs to handle the information of TCP connection and
    provide a TCP-like ARQ function.

    The adapter packs all data that we need to transmit. Then, the UDPServer
    transmits the data over IR's UDP protocol.


Data Packet Format:
    +--------------------+-----------------------+
    |       field        |        byte(s)        |
    +--------------------+-----------------------+
    |       SERIAL       |           4           |
    +--------------------+-----------------------+
    |       AMOUNT       |           1           |
    +--------------------+-----------------------+
    |        TYPE        |           1           |
    +--------------------+-----------------------+
    |      BODY.LEN      |           2           |
    +--------------------+-----------------------+
    |        BODY        |       BODY.LEN        |
    +--------------------+-----------------------+


Field Description:

    SERIAL:
        The serial number of the data packet.
        Range: 0x00000000 - 0xFFFFFFFF

        The serial numbers are unique and continuous in each data packet.
        It's in order to provide reliability for the UDP communication.
        The adapter will check the serial number and make sure that
        these serial numbers are continuous.

        If the packet is an ACK/UNA packet, the SERIAL field should be ignored.
        Serial number in ACK/UNA packet is not in the queue of serial numbers.
        It's just in order to keep the format of the packets.
        

    AMOUNT:
        The amount of small data blocks in one window
        Range: 0x00 - 0xFF

        The transmission of IR TOU is not like a stream.
        I decided to make it like a "block transmission system".
        TOUAdapter will cut the data from TCP stream into continuous blocks.
        Then, each block will be transmitted in one window.
        Close the window once its transmission is complete then open next one.
        Before transmitting, the block will be cut again into smaller blocks.
        The AMOUNT field means that how many small blocks in this window just
        like the "window size" in TCP.

        This field is necessary when TYPE != 0x03, AMOUNT is also useful for
        other types of packets. In fact, I want to transmit all the other types
        of packets like the TCP data block.

    TYPE:
        The type of data packet.
        Range: 0x00 - 0xFF

        There are 5 kinds of the data packet:
            0x00: information of TCP connection
            0x01: TCP connection status reporting
            0x02: data from TCP stream
            0x03: ACK/UNA
            0x04: asking for lost packet

    BODY.LEN:
        The length of BODY.
        Range: 0x0000 - 0xFFFF

    BODY:
        A container contains the data or any other information that we need.
        It has several kind of structures depend on the TYPE.

        Body Format:
            TYPE == 0x00: information of TCP connection:
                Format:
                    +--------------------+-----------------------+
                    |       field        |        byte(s)        |
                    +--------------------+-----------------------+
                    |      DEST.AF       |       BODY.LEN        |
                    +--------------------+-----------------------+

                Description:
                    DEST.AF:
                        The IPV4 address and TCP port of the destination.
                        Range: 0x000000000000 - 0xFFFFFFFFFFFF
                        First 4 bytes are the IPV4 address.
                        Last 2 bytes are the TCP port.

            TYPE == 0x01: TCP connection status reporting:
                Format:
                    +--------------------+-----------------------+
                    |       field        |        byte(s)        |
                    +--------------------+-----------------------+
                    |    CONN.STATUS     |           1           |
                    +--------------------+-----------------------+

                Description:
                    CONN.STATUS:
                        The status of the tcp connection.
                        Range: 0x00 - 0xFF
                        Values:
                            0x00: didn't connect
                            0x01: connecting
                            0x02: connected
                            0x03: disconnected

            TYPE == 0x02: data from TCP stream:
                Format:
                    +--------------------+-----------------------+
                    |       field        |        byte(s)        |
                    +--------------------+-----------------------+
                    |     DATA.SERIAL    |           4           |
                    +--------------------+-----------------------+
                    |        DATA        |       len(DATA)       |
                    +--------------------+-----------------------+

                Description:
                    DATA.SERIAL:
                        The serial number of the data block in current packet.
                        This is different from the SERIAL field in data packet.
                        DATA.SERIAL only marks the order of the data blocks
                        in TCP stream. And it's continuous too.

                    DATA:
                        Data from TCP stream.

            TYPE == 0x03: ACK/UNA:
                Format:
                    +--------------------+-----------------------+
                    |       field        |        byte(s)        |
                    +--------------------+-----------------------+
                    |      ACK.TYPE      |           1           |
                    +--------------------+-----------------------+
                    |    RECVD.SERIAL    |           4           |
                    +--------------------+-----------------------+

                Description:
                    ACK.TYPE:
                        ACK or UNA.
                        Range: 0x00 - 0xFF
                        Values:
                            0x00: ACK
                            0x01: UNA

                    RECVD.SERIAL:
                        The serial number of the received data packet.
                        Range: 0x00000000 - 0xFFFFFFFF

            TYPE == 0x04: asking for lost packet:
                Format:
                    +--------------------+-----------------------+
                    |       field        |        byte(s)        |
                    +--------------------+-----------------------+
                    |    LOST.SERIAL     |           4           |
                    +--------------------+-----------------------+

                Description:
                    LOST.SERIAL:
                        The serial number of the lost data packet.
                        Range: 0x00000000 - 0xFFFFFFFF
'''


class PacketMaker():

    @classmethod
    def make_tou_packet(cls, serial=0, amount=0, type_=None, dest_af=None,
                        conn_status=None, data=None, data_serial=None,
                        ack_type=None, recvd_serial=None, lost_serial=None):
        '''make a TOU data packet

        :param type_: the type of this packet. Type: int
        :param serial: serial number of this packet. Type: int
        :param amount: the amount of small data blocks in one window. Type: int
        :param dest_af: IPV4 address and port of dest. Structure: ('1.1.1.1', 1)
        :param conn_status: status code of the TCP connection. Type: int
        :param data: data from TCP stream. Type: bytes
        :param data_serial: the serial number of the data block. Type: int
        :param ack_type: a code that represents ACK or UNA. Type: int
        :param recvd_serial: serial number of the received packet. Type: int
        :param lost_serial: serial number of the lost packet. Type: int

        :rtype: bytes
        '''

        if type_ == 0:
            body = AfConverter.ipv4_af_2_bytes(dest_af)
        elif type_ == 1:
            body = struct.pack('B', conn_status)
        elif type_ == 2:
            data_serial = struct.pack('I', data_serial)
            body = data_serial + data
        elif type_ == 3:
            ack_type = struct.pack('B', ack_type)
            recvd_serial = struct.pack('I', recvd_serial)
            body = ack_type + recvd_serial
        elif type_ == 4:
            body = struct.pack('I', lost_serial)

        serial = struct.pack('I', serial)
        amount = struct.pack('B', amount)
        type_ = struct.pack('B', type_)
        body_len = struct.pack('H', len(body))
        return serial + amount + type_  + body_len + body


class PacketParser():

    @classmethod
    def parse_tou_packet(cls, raw_data):
        '''parse a TOU data packet

        :param raw_data: just data. Type: bytes

        :rtype: dict
        :rstruct: {
                    'serial': int,
                    'amount': int,
                    'type': int,
                    'dest_af': ('0.0.0.0', 65535) or None,
                    'conn_status': int or None,
                    'data': bytes or None,
                    'data_serial': int or None,
                    'ack_type': int or None,
                    'recvd_serial': int or None,
                    'lost_serial': int or None,
                  }
        '''

        # We don't need any authentication here.
        # The UDPServer will provide reliability for the received data.
        res = {'serial': None,
               'amount': None,
               'type': None,
               'dest_af': None,
               'conn_status': None,
               'data': None,
               'data_serial': None,
               'ack_type': None,
               'recvd_serial': None,
               'lost_serial': None}

        i = 0
        res['serial'] = struct.unpack('I' ,raw_data[i: i + 4])[0]
        i += 4

        res['amount'] = struct.unpack('B', raw_data[i: i + 1])[0]
        i += 1

        type_ = struct.unpack('B', raw_data[i: i + 1])[0]
        res['type'] = type_
        i += 1

        body_len = struct.unpack('H', raw_data[i: i + 2])[0]
        i += 2

        body = raw_data[i: i + body_len]

        if type_ == 0:
            res['dest_af'] = AfConverter.bytes_2_ipv4_af(body)
        elif type_ == 1:
            res['conn_status'] = struct.unpack('B', body)[0]
        elif type_ == 2:
            res['data_serial'] = struct.unpack('I', body[:4])[0]
            res['data'] = body[4:]
        elif type_ == 3:
            res['ack_type'] = struct.unpack('B', body[:1])[0]
            res['recvd_serial'] = struct.unpack('I', body[1:])[0]
        elif type_ == 4:
            res['lost_serial'] = struct.unpack('I', body)[0]
        return res


class TOUAdapter():

    ''' Overview

        +---------------------+-------------+------------------------------+
        |                     |             |                              |
        |     +-------------> |     TOU     | -----------------------+     |
        |     |               |             |              ^         |     |
        |     |               | PacketMaker |              |         V     |
        +------------+        |             |              |   +-----------+
        |     |      |        +-------------+              |   |     |     |
    --->|-----+      |                                     |   |     +-----|--->
        |            |                                     |   |           |
        |            |                   +------------+    |   |           |
        |            |                   |            |    |   |           |
        | TCPHandler |                   |    ARQ     |    |   |    UDP    |
        |            |     TOUAdapter    |            |----+   |           |
        | Interface  |                   | Controller |    |   | Interface |
        |            |                   |            |    |   |           |
        |            |                   +------------+    |   |           |
        |            |                                     |   |           |
    <---|-----+      |                                     |   |     +-----|<---
        |     |      | +----------+     +--------------+   |   |     |     |
        +------------+ |          |     |              |   |   +-----------+
        |     ^        | TCP Data |     |     TOU      |   V         |     |
        |     |        |          | <-- |              | <-----------+     |
        |     +------- | Storage  |     | PacketParser |                   |
        |              |          |     |              |                   |
        +--------------+----------+-----+--------------+-------------------+
    '''

    def __init__(self, epoll, arq_repeater, config, is_local):
        self._serial = -1
        self._db_serial = -1
        self._epoll = epoll
        self._arq_repeater = arq_repeater
        self._config = config
        self._is_local = is_local

        self._udp_svr_port = config['tou_listen_udp_port']
        self._max_serial = config.get('tou_pkt_max_serial') or 4096
        self._max_db_serial = config.get('tou_tcp_db_max_serial') or 4096
        self._min_tu = config.get('tou_min_tu') or 64
        self._max_tu = config.get('tou_max_tu') or 4096
        self._rto = config.get('tou_arq_rto') or 0.2
        max_up_wd_size = config.get('tou_max_upstm_window_size') or 32
        max_dn_wd_size = config.get('tou_max_dnstm_window_size') or 128
        self._max_wd_size = max_up_wd_size if is_local else max_dn_wd_size

        self._udp_sock = self._init_udp_socket()
        self._arq_ctlr = ARQController(self, arq_repeater, self._udp_sock,
                                       self._udp_svr_port, self._min_tu,
                                       self._max_tu, self._max_wd_size)
        self._buffer_size = self._arq_ctlr.max_db_size

        # TCP Data Storage
        self._stream_buffer = []

    def _next_serial(self):
        serial = self._serial + 1
        if serial > self._max_serial:
            serial = 0
        self._serial = serial
        return serial

    # db --> data block
    def _next_db_serial(self):
        serial = self._db_serial + 1
        if serial > self._max_db_serial:
            serial = 0
        self._db_serial = serial
        return serial

    def rand_rpt_interval(self):
        intv = random.uniform(-0.015, 0.015) + self._rpt_interval
        return intv if intv > 0.01 else 0.01

    def _init_udp_socket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setblocking(False)
        sock.bind(('127.0.0.1', 0))
        fd = sock.fileno()
        logging.debug('[TOU] Adapter created UDP socket fd: %d' % fd)
        return sock

    def handle_fpacket(self, dest_af):
        serial = self._next_serial()
        packet = PacketMaker.make_tou_packet(serial=serial, type_=0,
                                             dest_af=dest_af)
        self._udp_out(serial, packet)

    def tcp_in(self, data):
        pass

    def tcp_out(self):
        pass

    def udp_in(self, packet):
        pass

    def udp_out(self, serial, packet):
        interval = self.rand_rpt_interval()
        self._arq_repeater.add_repetition(interval, serial,
                                          packet, self._udp_sock)

    @property
    def udp_fd(self):
        return self._udp_sock.fileno()


class ARQController():

    '''The selective repeat ARQ is the most suitable mode for IR TOU.

    We have continuous serial numbers in all of TOU packets and
    another bunch of serial numbers for all of TCP data blocks.
    We just need to make sure that every serial number has been received.
    '''

    def __init__(self, tou_adapter, arq_repeater, udp_sock,
                       tou_udp_svr_port, min_tu, max_tu, max_wd_size):
        self._tou_adapter = tou_adapter
        self._arq_repeater = arq_repeater
        self._udp_sock = udp_sock
        self._tou_udp_svr_af = ('127.0.0.1', tou_udp_svr_port)

        self._min_tu = min_tu
        self._max_tu = max_tu
        self._max_wd_size = max_wd_size    # max window size
        self._max_db_size = max_wd_size * max_tu    # max data block size

        self._serial_sent = -1
        self._serial_recv = -1
        self._window = None

    def transmit_data_block(self, block):
        interval = self._tou_adapter.rand_rpt_interval()
        self._window = Window(self._max_wd_size, self._min_tu, self._max_tu,
                              self._tou_adapter, self._arq_repeater, interval,
                              data_block=block)
        self._window.transmit()

    def send_ack(self, recvd_serial):
        packet = PacketMaker.make_tou_packet(type_=3, ack_type=0,
                                             recvd_serial=recvd_serial)
        self.udp_sock.sendto(packet, self._tou_udp_svr_af)

    def send_una(self, recvd_serial):
        packet = PacketMaker.make_tou_packet(type_=3, ack_type=1,
                                             recvd_serial=recvd_serial)
        self.udp_sock.sendto(packet, self._tou_udp_svr_af)

    def on_pkt_recv(self, packet):
        pass

    @property
    def max_db_size(self):
        return self._max_db_size


class Window():

    def __init__(self, max_window_size, min_tu, max_tu,
                       tou_adapter, arq_repeater, rpt_interval,
                       data_block=None, packet=None, serial=None):
        self._size = None
        self._packets = {}
        self.transmitted_serial = []

        self._max_tu = max_tu
        self._min_tu = min_tu
        self._max_wd_size = max_window_size
        self._tou_adapter = tou_adapter
        self._arq_repeater = arq_repeater
        self._rpt_interval = rpt_interval

        # Actually, data_block and packet won't be passed in at the same time.
        # This serial is belong to the packet.
        self._fill(data_block, packet, serial)

    def _fill(self, data_block=None, packet=None, serial=None):
        if data_block:
            self._packets = self._block_2_packets(data_block)
        elif packet and serial:
            self._packets = {serial: packet}
        else:
            logging.error('[TOU] Window filling error.')
        self._size = len(self._packets)

    def _block_2_packets(self, block):
        ''' 数据切割方法

        当取得的数据块的大小满足以下条件时，直接使用max_tu作为切块大小：
            (max_tu - 1) * 最大块数 < 总长度

        当数据块大小未达到上限时：
            用x表示实际可用的最小块大小
            x的计算方式：x = 数据块总长度 / 最大块数

            此时有2种情况：
                min_tu < x < max_tu:
                    在x到max_tu之间取随机值作为实际切块大小

                x < min_tu < max_tu:
                    在min_tu到max_tu之间取随机值作为实际切块大小
        '''

        db_len = len(block)
        if (self._max_tu - 1) * self._max_wd_size < db_len:
            block_size = self._max_tu
        else:
            min_block_size = db_len / self._max_wd_size
            int_min_bs = int(min_block_size)
            if int_min_bs < min_block_size:
                min_block_size = int_min_bs + 1
            else:
                min_block_size = int_min_bs

            if self._min_tu < min_block_size:
                block_size = random.randint(min_block_size, self._max_tu)
            else:
                block_size = random.randint(self._min_tu, self._max_tu)

        small_blocks = self._cut(block, block_size)
        amount = len(small_blocks)
        packets = {}
        for small_blk in small_blocks:
            serial = self._tou_adapter._next_serial()
            db_serial = self._tou_adapter._next_db_serial()
            packet = PacketMaker.make_tou_packet(serial=serial,
                                                 amount=amount,
                                                 type_=2,
                                                 data_serial=db_serial,
                                                 data=small_blk)
            packets[serial] = packet
        return packets

    def _cut(self, block, size):
        db_len = len(block)
        blocks = []

        i = 0
        while i < db_len:
            small_blk = block[i: i + size]
            blocks.append(small_blk)
            i += size
        return blocks

    def transmit(self):
        for serial, packet in self._packets.items():
            self._repeater.add_repetition(self._rpt_interval, serial,
                                          packet, self._udp_sock)
            self.transmitted_serial.append(serial)


class ARQRepeater(Thread):

    def __init__(self, tou_udp_svr_port):
        Thread.__init__(self, daemon=True)

        self._running = False
        self._dest_af = ('127.0.0.1', tou_udp_svr_port)
        self._evt = Event()
        self._schd = sched.scheduler()
        self.task_list = []
        self.task_map = {}    # {tou_packet_serial: task}

    def _activate(self):
        if not self.running:
            self.evt.set()

    def _add_task(self, interval, func, serial):
        def task():
            # I don't need parameters here
            # so I removed the parameter "args" and "kwargs"
            if task in self.task_list:
                func()
                self._schd.enter(interval, 1, task)

        self.task_list.append(task)
        self.task_map[serial] = task
        task()
        self._activate()

    def add_repetition(self, interval, serial, packet, sock):
        def send():
            sock.sendto(packet, self._dest_af)

        self._add_task(interval, send, serial)

    def rm_repetition(self, serial):
        task = self.task_map.get(serial)
        if task and task in self.task_list:
            self.task_list.remove(task)
            del(self.task_map[serial])

    def run(self):
        while True:
            self.evt.wait()
            self.running = True
            self.s.run()
            self.evt.clear()
            self.running = False
