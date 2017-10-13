#!/usr/bin/python3.6
#coding: utf-8

import struct

from ir.protocol.base import AfConverter


__all__ = []



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
        The serial numbers are unique and continuous in each data packet
        of a TCP connection.  It's in order to provide reliability for
        the UDP communication. The adapter will check the serial number
        and make sure that serial numbers are continuous.

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
    def make_tou_packet(cls, serial=None, type_=None, dest_af=None,
                        conn_status=None, data=None, data_serial=None,
                        ack_type=None, recvd_serial=None, lost_serial=None):
        '''make a TOU data packet

        :param type_: the type of this packet. Type: int
        :param serial: serial number of this packet. Type: int
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
        type_ = struct.pack('B', type_)
        return serial + type_ + body


class PacketParser():

    @classmethod
    def parse_tou_packet(cls, raw_data):
        '''parse a TOU data packet

        :param raw_data: just data. Type: bytes

        :rtype: dict
        :rstruct: {
                    'serial': int,
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
