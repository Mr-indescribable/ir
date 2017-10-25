#!/usr/bin/python3.6
#coding: utf-8

import sys
import socket
import logging

from ir.server.base import TCPServer as BaseTCPServer
from ir.server.base import UDPServer as BaseUDPServer
from ir.protocol.tou import ARQRepeater


__all__ = ['TCPServer', 'UDPServer']


UDP_BUFFER_SIZE = 65536


def after_init(self):
    def _exit():
        logging.error('[TOU] Invalid TOU configuration.')
        sys.exit(1)

    tou_udp_pt = self._config.get('tou_listen_udp_port')
    if not isinstance(tou_udp_pt, int):
        _exit()

    if self._is_local:
        tou_remote_udp_pt = self._config.get('tou_remote_udp_port')
        if not isinstance(tou_remote_udp_pt, int):
            _exit()


class TCPServer(BaseTCPServer):

    _server_type = 'TOU_TCP'

    _after_init = after_init

    def _load_handler(self):
        from ir.handler.tou import TCPHandler
        self.TCPHandler = TCPHandler

    def _before_run(self):
        self._arq_repeater = ARQRepeater(self._config['tou_listen_udp_port'])
        self._arq_repeater.start()
        logging.info('[TOU] Running TCP server under TCP over UDP mode')


class UDPServer(BaseUDPServer):

    _server_type = 'TOU_UDP'

    _after_init = after_init

    def _load_handler(self):
        from ir.handler.tou import UDPHandler
        from ir.handler.base import UDPMultiTransmitHandler

        self.UDPHandler = UDPHandler
        self.UDPMultiTransmitHandler = UDPMultiTransmitHandler

    def _init_socket(self, listen_addr=None, listen_port=None):
        listen_addr = listen_addr or '127.0.0.1'
        listen_port = listen_port or self._config['tou_listen_udp_port']
        if not listen_port:
            logging.error('[TOU] Invalid TOU config: tou_listen_udp_port')
            sys.exit(1)
        addr_info = socket.getaddrinfo(listen_addr, listen_port, 0,
                                       socket.SOCK_DGRAM, socket.SOL_UDP)
        if len(addr_info) == 0:
            logging.error('[TOU] failed to do getaddrinfo() for tou_udp_server')
            sys.exit(1)
        af, stype, proto, canname, sa = addr_info[0]
        sock = socket.socket(af, stype, proto)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setblocking(False)
        sock.bind(sa)
        logging.info('[TOU] UDP server is listening at %s:%d' % (
                                          self._config['listen_addr'],
                                          self._config['listen_udp_port']))
        return sock

    def _local_server_socket_recv(self):
        data, src = self._local_sock.recvfrom(UDP_BUFFER_SIZE)
        dest = ('127.0.0.1', self._tou_local_fp)
        return data, src, dest
