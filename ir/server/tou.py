#!/usr/bin/python3.6
#coding: utf-8

import select
import logging

from ir.server.base import TCPServer as BaseTCPServer
from ir.server.base import UDPServer as BaseUDPServer


__all__ = ['TCPServer', 'UDPServer']


UDP_BUFFER_SIZE = 65536


class TCPServer(BaseTCPServer):

    def _load_handler(self):
        from ir.handler.tou import TCPHandler
        self.TCPHandler = TCPHandler

    def _after_init(self):
        self._tou_udp_sock = self._init_tou_udp_server_socket()
        self._tou_udp_fd = self._tou_udp_sock.fileno()
        self._epoll.register(self._tou_udp_fd, select.EPOLLIN | select.EPOLLERR)

    def _init_tou_udp_server_socket(self):
        listen_addr = self._config.get('listen_addr')
        listen_port = self._config.get('tou_listen_udp_port')
        addr_info = socket.getaddrinfo(listen_addr, listen_port, 0,
                                       socket.SOCK_DGRAM, socket.SOL_UDP)
        if len(addr_info) == 0:
            logging.error('[TOU] failed to do getaddrinfo() for tou_udp_server')
            import sys
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


class UDPServer(BaseUDPServer):

    def _load_handler(self):
        from ir.handler.tou import UDPHandler
        from ir.handler.base import UDPMultiTransmitHandler

        self.UDPHandler = UDPHandler
        self.UDPMultiTransmitHandler = UDPMultiTransmitHandler

    def _after_init(self):
        def _exit():
            logging.error('[TOU] Invalid feeding ports in config file')
            import sys
            sys.exit(1)

        self._tou_fp = self._config.get('tou_feeding_port')
        if not isinstance(self._tou_fp, int):
            _exit()

        if self._is_local:
            self._tou_remote_fp = self._config.get('tou_remote_feeding_port')
            if not isinstance(self._tou_remote_fp, int):
                _exit()

    def _local_server_socket_recv(self):
        data, src = self._local_sock.recvfrom(UDP_BUFFER_SIZE)
        dest = ('127.0.0.1', self._tou_local_fp)
        return data, src, dest
