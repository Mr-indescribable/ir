#!/usr/bin/python3.6
#coding: utf-8

import os
import time
import sched
import select
import socket
import struct
import random
import logging
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
    |        TIME        |           8           |
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
        
    TIME:
        Timestamp.
        Range: 0x0000000000000000 - 0xFFFFFFFFFFFFFFFF

        This field is not like the TIME field in base UDP protocol.
        It will only be filled when it's necessary.
        In other case, it should be 0x0000000000000000.

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
                            0x00: not connected
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


UDP_BUFFER_SIZE = 65536


class PacketMaker():

    @classmethod
    def make_tou_packet(cls, serial=0, amount=1, type_=None, dest_af=None,
                             conn_status=None, data=None, data_serial=None,
                             ack_type=None, recvd_serial=None,
                             lost_serial=None, time_=None):
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
        :param time_: timestamp of this packet from time.time(). Type: int/float

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
        time_ = int((time_ or 0) * 10000000)
        time_ = struct.pack('L', time_)
        amount = struct.pack('B', amount)
        type_ = struct.pack('B', type_)
        body_len = struct.pack('H', len(body))
        return serial + time_ + amount + type_  + body_len + body


class PacketParser():

    @classmethod
    def parse_tou_packet(cls, raw_data):
        '''parse a TOU data packet

        :param raw_data: just data. Type: bytes

        :rtype: dict
        :rstruct: {
                    'serial': int,
                    'time': int,
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
               'time': None,
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

        res['time'] = struct.unpack('L' ,raw_data[i: i + 8])[0]
        i += 8

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


class Buffer():

    def __init__(self, tou_adapter, max_db_size):
        '''Overview:

            self._buffer = ['----------', '=========', '=========', '--------']
            self._marker = [    'DB'    ,    'PKT'   ,    'PKT'   ,    'DB'   ]
        '''

        self._buffer = []
        self._marker = []
        self._tou_adapter = tou_adapter
        self._max_db_size = max_db_size

    def buff_db(self, db):
        if len(self._buffer) > 0 and self._marker[-1] == 'DB':
            self._buffer[-1] += db
        else:
            self._buffer.append(db)
            self._marker.append('DB')
        self._tou_adapter.buffer_callback()

    def buff_packet(self, packet):
        '''store a packet

        We didn't make a real tou packet yet, it will be made when adapter going
        to send it. Here, we store a dict that contains the parameters we need

        :param packet: parameter container of a packet, type: dict
        '''

        self._buffer.append(packet)
        self._marker.append('PKT')
        self._tou_adapter.buffer_callback()

    def next_fragment(self):
        if self.stored:
            db = self._buffer[0]
            marker = self._marker[0]
            if marker == 'DB' and len(db) > self._max_db_size:
                d2r = db[:self._max_db_size]
                self._buffer[0] = db[self._max_db_size:]
                return d2r, marker
            else:
                return self._buffer.pop(0), self._marker.pop(0)
        return None, None

    def clean(self):
        self._buffer = []
        self._marker = []

    @property
    def stored(self):
        return bool(self._buffer)


class TOUAdapter():

    ''' Overview

        +---------------------+-------------+------------------------------+
        |                     |             |                              |
        |     +-------------> |     TOU     |       +-------------+        |
        |     |               |             |       |             |        |
        |     |               | PacketMaker | ----->|-------------|--------|--->
        +------------+        |             |       |             |        |
        |     |      |        +-------------+       |     ARQ     |        |
    --->|-----+      |                              |             |        |
        |            |                              |  Interface  |        |
        |            |                              |             |        |
        |            |                         +----|-------------|<----+  |
        | TCPHandler |                         |    |             |     |  |
        |            |       TOUAdapter        |    +-------------+     |  |
        | Interface  |                         |                        |  |
        |            |                         |                        |  |
        |            |                         |                        |  |
        |            |                         |               +-----------+
    <---|-----+      |                         V               |        |  |
        |     |      | +----------+     +--------------+       |        +--|<---
        +------------+ |          |     |              |       |    UDP    |
        |     ^        | TCP Data |     |     TOU      |       |           |
        |     |        |          | <-- |              |       | Interface |
        |     +------- | Storage  |     | PacketParser |       |           |
        |              |          |     |              |       |           |
        +--------------+----------+-----+--------------+-------+-----------+
    '''

    def __init__(self, arq_repeater, config, is_local, src, server_sock=None):
        self._serial = -1
        self._db_serial = -1

        # Before we close a TOU connection, we need to send FIN at both side.
        # Sending a FIN packet means that the TCP connection has been closed
        # at this side. Each side needs to send one and receive one. The first
        # FIN sender is defined as "proactive side", the second FIN sender is
        # defined as "passive side". The passive side need to send the final
        # data block after it receiving the ACK of the FIN.
        self._passive = None
        self._tcp_destroyed = False
        self._fin_sent = False
        self._fin_recvd = False
        self._disconnect_time = None
        # Just like the FIN_WAIT_* status in TCP but with a little difference.
        # fin_wait_1 means this side is waiting for the ACK of its FIN packet.
        # fin_wait_2 means this side is waiting for the FIN from the other side.
        self._fin_wait_1 = False
        self._fin_wait_2 = False
        # This ACK is belong to the final block
        self._final_ack_expecting = False
        self._final_block_expecting = False
        self._final_block_sent = False
        self._fb_last_recv_time = None
        # this flag means the transmission has been finished already
        # the UDP socket now can be closed safely
        self._transmission_finished = False

        self._arq_repeater = arq_repeater
        self._config = config
        self._is_local = is_local
        self._src = src
        # at local side, each adapter needs one UDP socket
        # at remote side, adapters use the TCPServer's server socket
        if self._is_local:
            self._udp_sock = self._init_udp_socket()
        else:
            self._udp_sock = server_sock

        local_udp_port = config['tou_listen_udp_port']
        self._udp_dest_af = ('127.0.0.1', local_udp_port) if is_local else src
        self._max_serial = config.get('tou_pkt_max_serial') or 4096
        self._max_db_serial = config.get('tou_tcp_db_max_serial') or 4096
        self._min_tu = config.get('tou_min_tu') or 64
        self._max_tu = config.get('tou_max_tu') or 4096
        self._rto = config.get('tou_arq_rto') or 0.25
        max_up_wd_size = config.get('tou_max_upstm_window_size') or 32
        max_dn_wd_size = config.get('tou_max_dnstm_window_size') or 128
        self._max_wd_size = max_up_wd_size if is_local else max_dn_wd_size

        self._arq_intf = ARQInterface(self._max_wd_size, self._min_tu,
                                      self._max_tu, self, arq_repeater,
                                      self._udp_sock, self._udp_dest_af)
        self._max_db_size = self._arq_intf.max_db_size
        self._buffer = Buffer(self, self._max_db_size)

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
        intv = random.uniform(-0.015, 0.015) + self._rto
        return intv if intv > 0.01 else 0.01

    def _init_udp_socket(self, af_2_bind=None):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setblocking(False)
        af_2_bind = af_2_bind or ('127.0.0.1', 0)
        sock.bind(af_2_bind)
        fd = sock.fileno()
        logging.debug('[TOU-UDP] Adapter created UDP socket fd: %d' % fd)
        return sock

    def rebuild_udp_sock(self):
        binded_af = self._udp_sock.getsockname()
        self._udp_sock.close()
        self._udp_sock = self._init_udp_socket(binded_af)
        logging.warn('[TOU-UDP] UDP socket rebuilt')

    def connect(self, dest_af):
        packet_params = {'type_': 0, 'dest_af': dest_af}
        self._buffer.buff_packet(packet_params)

    # tell the local side: connection ready at the remote side
    def feedback_conn_completed(self):
        packet_params = {'type_': 1, 'conn_status': 2}
        self._buffer.buff_packet(packet_params)

    def send_fin(self):
        # Here, we send the "status code 3" to tell the other side
        # that the TCP connection at this side has been closed.
        # Just like the FIN in TCP but with a little difference.

        if not self._fin_sent and not self._arq_intf.locked:
            time_ = time.time()
            serial = self._next_serial()
            packet = PacketMaker.make_tou_packet(serial=serial, type_=1,
                                                 conn_status=3, time_=time_)
            self._arq_intf.send_packet(packet, serial)
            self._fin_sent = True
            self._fin_wait_1 = True
            self._disconnect_time = int(time_ * 10000000)
            logging.debug('[TOU-UDP] FIN sent')
            return True
        return False

    def _send_next(self):
        data, type_ = self._buffer.next_fragment()
        if type_ == 'PKT':
            packet_params = data
            srl = self._next_serial()
            packet = PacketMaker.make_tou_packet(serial=srl, **packet_params)
            self._arq_intf.send_packet(packet, srl)
        elif type_ == 'DB':
            self._arq_intf.transmit_data_block(data)

    def send_buffered(self):
        if not self._arq_intf.locked:
            self._send_next()
            return True
        return False

    def buffer_callback(self):
        if not self.sending:
            self.send_buffered()

    def arq_intf_transmission_callback(self):
        if self._tcp_destroyed and not self._buffer.stored:
            self.send_fin()
        else:
            self.send_buffered()

    def tcp_in(self, data):
        if data:
            self._buffer.buff_db(data)
            logging.debug('[TOU-TCP] Adapter buffered %dB of data' % len(data))

    def _send_fb(self):
        if not self._final_block_sent:
            self._final_block_sent = True
            self._final_ack_expecting = True
            # send something to other side and let it know that
            # this side has received the ACK of the FIN
            db = os.urandom(random.randint(4, 128))
            self._buffer.buff_db(db)
            logging.debug('[TOU-UDP] FB sent')

    def on_udp_in(self, packet=None):
        if packet is None:
            packet, _ = self._udp_sock.recvfrom(UDP_BUFFER_SIZE)
        packet = PacketParser.parse_tou_packet(packet)
        type_ = packet['type']
        srl = packet['serial']

        if srl <= self._arq_intf._last_recvd_serial and type_ != 3:
            self._arq_intf.send_ack(srl)
            return None, None

        if type_ == 3 and self._fin_wait_1:
            self._arq_intf.on_packet_recv(packet)
            if not self._arq_intf.locked:
                self._fin_wait_1 = False
                fin_processed = self._fin_sent and self._fin_recvd
                if self._passive and fin_processed:
                    self._send_fb()
                else:
                    self._fin_wait_2 = True
                return None, None
        if self._final_block_expecting:
            if self._arq_intf.final_block_recvd(packet):
                self._transmission_finished = True
                self.update_last_recv_time()
                logging.debug('[TOU-UDP] FB received')
                return 'wait_for_destroy', None
        if type_ == 3 and self._final_ack_expecting:
            if self._arq_intf.final_ack_recvd(packet):
                self._transmission_finished = True
                self._arq_intf.close()
                return 'destroy', None
        return self._normal_udp_in(packet)

    def _normal_udp_in(self, packet):
        # if it returns packets, then the reception is completed
        recvd_packets = self._arq_intf.on_packet_recv(packet)
        if not recvd_packets:
            return None, None

        type_ = packet['type']

        # when type != 2, only one packet will be transmitted
        if type_ == 0:
            return 'connect', packet['dest_af']
        elif type_ == 1:
            conn_status = packet['conn_status']
            if conn_status in (0, 1):
                return 'wait', None
            elif conn_status == 2:
                return 'connected', None
            elif conn_status == 3:
                if self._fin_sent:
                    time_ = packet['time']
                    if self._disconnect_time > time_:
                        self._passive = True
                    elif self._disconnect_time == time_ and self._is_local:
                        self._passive = True
                    else:
                        self._passive = False
                else:
                    self._passive = True

                fin_processed = self._fin_sent and self._fin_recvd
                if not self._passive:
                    self._final_block_expecting = True
                elif fin_processed:
                    self._send_fb()

                self._fin_wait_2 = False
                self._fin_recvd = True
                logging.debug('[TOU-UDP] FIN received')
                return 'disconnect', None
        elif type_ == 2 and not self._tcp_destroyed:
            data = b''
            for pkt in recvd_packets:
                data += pkt['data']
            return 'transmit', data
        elif type_ == 4:
            # type 4 is not currently in use
            pass
        return None, None

    def update_last_recv_time(self):
        self._fb_last_recv_time = time.time()

    def on_tcp_destroyed(self):
        self._tcp_destroyed = True
        if not self._buffer.stored:
            self.send_fin()

    def destroy(self):
        # at remote side, we use the server socket in TOUAdapter
        if self._is_local:
            self._buffer.clean()
            self._udp_sock.close()
            self._udp_sock = None
        del self._arq_intf

    @property
    def udp_fd(self):
        return self._udp_sock.fileno()

    @property
    def fb_last_recv_time(self):
        return self._fb_last_recv_time

    @property
    def sending(self):
        return self._arq_intf.locked


class ARQInterface():

    '''The selective repeat ARQ is the most suitable mode for IR TOU.

    We have continuous serial numbers in all of TOU packets and
    another bunch of serial numbers for all of TCP data blocks.
    We just need to make sure that every serial number has been received.
    '''

    def __init__(self, max_wd_size, min_tu, max_tu, tou_adapter,
                       arq_repeater, udp_sock, udp_dest_af):
        self._tou_adapter = tou_adapter
        self._arq_repeater = arq_repeater
        self._udp_sock = udp_sock
        self._udp_dest_af = udp_dest_af

        self._min_tu = min_tu
        self._max_tu = max_tu
        self._max_wd_size = max_wd_size    # max window size
        self._max_db_size = max_wd_size * max_tu    # max data block size

        self._last_recvd_serial = -1
        self._window = None
        self._receiver = None
        # a locked ARQInterface can only transmit ACK/UNA packets
        self.__locked = False

    def transmit_data_block(self, data_block):
        if self.__locked:
            logging.error('[TOU] transmit_data_block: ARQInterface is locked')
            return False

        self.__locked = True
        self._window = Window(self._max_wd_size, self._min_tu,
                              self._max_tu, self._tou_adapter,
                              self._arq_repeater, self._udp_sock,
                              self._udp_dest_af, data_block=data_block)
        self._window.transmit()
        return True

    def send_packet(self, packet, serial):
        if self.__locked:
            logging.error('[TOU] send_packet: ARQInterface is locked')
            return False

        self.__locked = True
        self._window = Window(self._max_wd_size, self._min_tu,
                              self._max_tu, self._tou_adapter,
                              self._arq_repeater, self._udp_sock,
                              self._udp_dest_af, packet=packet, serial=serial)
        self._window.transmit()
        return True

    def send_ack(self, recvd_serial):
        packet = PacketMaker.make_tou_packet(type_=3, ack_type=0,
                                             recvd_serial=recvd_serial)
        self._udp_sock.sendto(packet, self._udp_dest_af)
        logging.debug('[TOU-UDP] ACK sent, serial: %d' % recvd_serial)

    def send_una(self, recvd_serial):
        packet = PacketMaker.make_tou_packet(type_=3, ack_type=1,
                                             recvd_serial=recvd_serial)
        self._udp_sock.sendto(packet, self._udp_dest_af)
        logging.debug('[TOU-UDP] UNA sent, serial: %d' % recvd_serial)

    def on_packet_recv(self, packet):
        srl = packet['serial']
        r_srl = packet['recvd_serial']
        type_ = packet['type']

        # type == 3: ACK/UNA
        # if we don't have a window instance here, then the ack must be invalid
        if type_ == 3 and self._window:
            ack_tp = packet['ack_type']
            if (ack_tp == 0 and self._window.received_correct_ack(r_srl)) or\
               (ack_tp == 1 and self._window.received_correct_una(r_srl)):
                if self._window.completed:
                    self._window = None
                    self.__locked = False
                    logging.debug('[TOU] Data block transmission completed')
                    self._tou_adapter.arq_intf_transmission_callback()
        # type != 3 stream data or other information packet
        elif type_ != 3:
            if not self._receiver:
                self._receiver = Receiver(packet['amount'],
                                          self._last_recvd_serial+1)

            if self._receiver.received_correct_packet(packet):
                self.send_ack(srl)
                if self._receiver.completed:
                    self._last_recvd_serial = self._receiver.last_serial
                    # self.send_una(self._last_recvd_serial)
                    packets = self._receiver.dump()
                    self._receiver = None
                    logging.debug('[TOU] Data block received')
                    return packets

    def final_block_recvd(self, packet):
        # This packet is a part of the final data block which TOUAdapter sends.
        # Once the other side received a ACK packet of this final block,
        # it can know that udp socket can be closed safely.
        if not self._receiver:
            self._receiver = Receiver(packet['amount'],
                                      self._last_recvd_serial+1)

        if self._receiver.received_correct_packet(packet):
            # We have to make sure the other side has received the final ACK
            # The way to ensure this is expect it stop sending the final block.
            # So, the passive side cannot close UDP socket proactively.
            self.send_ack(packet['serial'])
            self._tou_adapter.update_last_recv_time()
            self._last_recvd_serial = self._receiver.tail_serial
            return True
        return False

    def final_ack_recvd(self, packet):
        type_ = packet['type']
        recvd_srl = packet['recvd_serial']

        if type_ == 3 and self._window:
            ack_tp = packet['ack_type']
            if ack_tp == 0 and self._window.received_correct_ack(recvd_srl):
                return True
        return False

    def close(self):
        if self._window:
            self._window.close()
        self._window = None
        self._receiver = None

    def __del__(self):
        self.close()

    @property
    def max_db_size(self):
        return self._max_db_size

    @property
    def locked(self):
        return self.__locked


class Receiver():

    def __init__(self, amount, first_serial):
        self._amount = amount
        self._first = first_serial

        end = self._first + amount
        self._serials = [s for s in range(self._first, end)]
        self._unrecvd_serials = list(self._serials)    # copy
        # The "tail serial" is the "rightmost one" in the sorted received queue
        # e.g. :
        #    self._serials  = [0, 1, 2, 3, 4, 5]
        #    received_queue = [0, 4, 1, 2]
        #    tail_serial    = 4
        self._tail_serial = -1

        self.__completed = False
        self._buffer = {}    # {serial: packet}

    def received_correct_packet(self, packet):
        srl = packet['serial']
        if srl in self._unrecvd_serials:
            self._unrecvd_serials.remove(srl)
            self._buffer[srl] = packet

            if srl > self._tail_serial:
                self._tail_serial = srl

            if not self._unrecvd_serials:
                self.__completed = True
            return True
        return False

    def dump(self):
        return [self._buffer[srl] for srl in self._serials]

    @property
    def tail_serial(self):
        return self._tail_serial

    @property
    def last_serial(self):
        return self._serials[-1]

    @property
    def completed(self):
        return self.__completed


class Window():    # or sender, transmitter, whatever

    def __init__(self, max_wd_size, min_tu, max_tu, tou_adapter,
                       arq_repeater, udp_sock, udp_dest_af,
                       data_block=None, packet=None, serial=None):
        self._size = None
        self.__completed = False
        self._packets = {}
        # Unacknowledged serials, they are also the repeating serials.
        self.unackd_serials = []

        self._max_tu = max_tu
        self._min_tu = min_tu
        self._max_wd_size = max_wd_size
        self._tou_adapter = tou_adapter
        self._arq_repeater = arq_repeater
        self._udp_sock = udp_sock
        self._udp_dest_af = udp_dest_af
        self._rpt_interval = self._tou_adapter.rand_rpt_interval()
        self._adapter_id = id(self._tou_adapter)

        # Actually, data_block and packet won't be passed in at the same time.
        # This serial is belong to the packet.
        self._fill(data_block, packet, serial)

    def _fill(self, data_block=None, packet=None, serial=None):
        if data_block:
            self._packets = self._block_2_packets(data_block)
        elif packet and isinstance(serial, int):
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
        for srl, packet in self._packets.items():
            self._arq_repeater.add_repetition(self._rpt_interval, srl, packet,
                                              self._udp_sock, self._udp_dest_af,
                                              self._adapter_id)
            self.unackd_serials.append(srl)

    def received_correct_ack(self, serial):
        logging.debug('[TOU-UDP] ACK received, serial: %d' % serial)
        if serial in self.unackd_serials:
            self.unackd_serials.remove(serial)
            self._arq_repeater.rm_repetition(serial, self._adapter_id)

            if not self.unackd_serials:
                self.__completed = True
            return True
        return False

    def received_correct_una(self, serial):
        logging.debug('[TOU-UDP] UNA received, serial: %d' % serial)
        if serial in self.unackd_serials:
            node = self.unackd_serials.index(serial) + 1
            ackd_serials = self.unackd_serials[:node]
            self.unackd_serials = self.unackd_serials[node:]
            for ackd_serial in ackd_serials:
                self._arq_repeater.rm_repetition(ackd_serial, self._adapter_id)

            if not self.unackd_serials:
                self.__completed = True
            return True
        return False

    def close(self):
        for srl in self.unackd_serials:
            self._arq_repeater.rm_repetition(srl, self._adapter_id)

    @property
    def completed(self):
        return self.__completed


class ARQRepeater(Thread):

    def __init__(self):
        Thread.__init__(self, daemon=True)

        self._running = False
        self._evt = Event()
        self._schd = sched.scheduler()
        self.task_list = []
        self.task_map = {}    # {"adapter_id-pkt_serial": task}

    def _activate(self):
        if not self._running:
            self._evt.set()

    def _gen_task_key(self, adapter_id, serial):
        return '%d-%d' % (adapter_id, serial)

    def _add_task(self, interval, func, serial, adapter_id):
        def repeat():
            if id(func) in self.task_list:
                func()
                self._schd.enter(interval, 1, repeat)

        self.task_list.append(id(func))
        task_key = self._gen_task_key(adapter_id, serial)
        self.task_map[task_key] = func
        repeat()
        self._activate()

    def add_repetition(self, interval, serial, packet,
                             sock, dest_af, adapter_id):
        def send():
            try:
                sock.sendto(packet, dest_af)
            except OSError:
                logging.warn('[TOU-UDP] Socket closed, remove repetition')
                self.rm_repetition(serial, adapter_id)

        self._add_task(interval, send, serial, adapter_id)

    def rm_repetition(self, serial, adapter_id):
        task_key = self._gen_task_key(adapter_id, serial)
        task = self.task_map.get(task_key)
        tid = id(task)
        if tid in self.task_list:
            self.task_list.remove(tid)
            del(self.task_map[task_key])

    def run(self):
        while True:
            self._evt.wait()
            self._running = True
            self._schd.run()
            self._evt.clear()
            self._running = False
