#!/usr/bin/python3.6
#coding: utf-8

import sys
import time
import select
import socket
import logging
from threading import Thread

from ir.crypto import Cryptor
from ir.server.base import SrcExclusiveItems, ExpiredUDPSocketCleaner
from ir.server.base import TCPServer as BaseTCPServer
from ir.server.base import UDPServer as BaseUDPServer
from ir.protocol.tou import ARQRepeater


__all__ = ['TCPServer', 'UDPServer']


UDP_BUFFER_SIZE = 65536


def after_init(self):
    def _exit():
        logging.error('[TOU] Invalid TOU configuration.')
        sys.exit(127)

    tou_udp_pt = self._config.get('tou_listen_udp_port')
    if not isinstance(tou_udp_pt, int):
        _exit()

    if self._is_local:
        tou_remote_tcp_pt = self._config.get('tou_remote_tcp_port')
        tou_remote_udp_pt = self._config.get('tou_remote_udp_port')
        udp_multi_remote = self._config.get('tou_udp_multi_remote')
        if not isinstance(tou_remote_tcp_pt, int):
            _exit()
        if (not isinstance(tou_remote_udp_pt, int) and
                not isinstance(udp_multi_remote, dict)):
            _exit()


class TCPServer(BaseTCPServer):

    _server_type = 'TOU_TCP'

    _after_init = after_init

    def _remove_handler(self, fd=None, src_port=None):
        if fd in self._fd_2_handler:
            del self._fd_2_handler[fd]
        # only for remote
        if src_port in self._udp_src_port_2_handler:
            del self._udp_src_port_2_handler[src_port]

    def _load_handler(self):
        from ir.handler.tou import TCPHandler
        self.TCPHandler = TCPHandler

    def _before_run(self):
        # For remote TPCServer's server_socket. Structure: {src_port: handler}
        self._udp_src_port_2_handler = {}

        self._arq_repeater = ARQRepeater()
        self._arq_repeater.start()
        self._tou_udp_socket_cleaner = TOUUDPSocketCleaner(self)
        self._tou_udp_socket_cleaner.start()
        logging.info('[TOU-TCP] Running TCP server under TCP over UDP mode')

    def _init_socket(self, so_backlog=1024):
        listen_addr = '127.0.0.1'
        listen_port = self._config['tou_listen_tcp_port']

        if self._is_local:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
            sock.setblocking(False)
            sock.bind((listen_addr, listen_port))
            sock.listen(so_backlog)
        else:
            # as remote,  TCPServer need to communicate with UDPServer with UDP
            # so, it's a UDP socket
            self._poll_mode = select.EPOLLIN
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setblocking(False)
            sock.bind((listen_addr, listen_port))

        logging.info(
                '[TOU-TCP] TCP Server is listening at %s:%d' % (listen_addr,
                                                                listen_port)
                )
        return sock

    def _local_handle_event(self, fd, evt):
        handler = self._fd_2_handler.get(fd)
        if fd == self._server_sock_fd and not handler:
            try:
                local_sock, src = self._server_sock.accept()
                c_fd = local_sock.fileno()
                logging.info(
                    '[TOU-TCP] Accepted connection from %s:%d, fd: %d' % (*src,
                                                                          c_fd)
                    )
                self.TCPHandler(self, self._epoll, self._config,
                                self._arq_repeater, self._is_local,
                                src, local_sock)
            except (OSError, IOError) as e:
                error_no = tools.errno_from_exception(e)
                if error_no in (errno.EAGAIN, errno.EINPROGRESS,
                                errno.EWOULDBLOCK):
                    return
        else:
            if handler:
                handler.handle_event(fd, evt)
            else:
                logging.warn('[TOU-TCP] fd removed')

    def _remote_handle_event(self, fd, evt):
        if fd == self._server_sock_fd:    # UDP in
            data, src = self._server_sock.recvfrom(UDP_BUFFER_SIZE)
            src_port = src[1]
            handler = self._udp_src_port_2_handler.get(src_port)
            if not handler:
                handler = self._remote_new_handler(src)
            handler.handle_event(fd, evt, data)
        else:   # TCP event
            handler = self._fd_2_handler.get(fd)
            if handler:
                handler.handle_event(fd, evt)
            else:
                logging.warn('[TOU-TCP] fd removed')

    def _remote_new_handler(self, src):
        handler = self.TCPHandler(self, self._epoll, self._config,
                                  self._arq_repeater, self._is_local, src, None)
        self._udp_src_port_2_handler[src[1]] = handler
        return handler

    def remote_reset_handler(self, handler, evt, data, src):
        if not handler.tcp_destroyed:
            handler.destroy_tcp_sock()
        if not handler.udp_destroyed:
            handler.destroy_tou_adapter()

        handler = self._remote_new_handler(src)
        handler.handle_event(self._server_sock_fd, evt, data)
        logging.warn('[TOU-TCP] Reseted TCPHandler.')

    def handle_event(self, fd, evt):
        if self._is_local:
            self._local_handle_event(fd, evt)
        else:
            self._remote_handle_event(fd, evt)

    @property
    def server_sock(self):
        return self._server_sock

    @property
    def server_fd(self):
        return self._server_sock_fd


class TOUUDPSocketCleaner(Thread):

    def __init__(self, server, max_idle_time=4, poll_time=4):
        Thread.__init__(self, daemon=True)

        self._server = server
        self.max_idle_time = max_idle_time
        self.poll_time = poll_time

    def check_and_clean(self):
        now = time.time()
        if self._server._is_local:
            fds = list(self._server._fd_2_handler.keys())
            handlers = list(self._server._fd_2_handler.values())
            for fd, handler in zip(fds, handlers):
                if handler._waiting_for_destroy:
                    if now - handler.fb_last_recv_time > self.max_idle_time:
                        if handler.udp_destroyed:
                            self._server._remove_handler(fd)
                        else:
                            handler.destroy_tou_adapter()
        else:
            src_ports = (self._server._udp_src_port_2_handler.keys())
            handlers = (self._server._udp_src_port_2_handler.values())
            for src_port, handler in zip(src_ports, handlers):
                if handler._waiting_for_destroy:
                    if now - handler.fb_last_recv_time > self.max_idle_time:
                        if handler.udp_destroyed:
                            self._server._remove_handler(src_port=src_port)
                        else:
                            handler.destroy_tou_adapter()

    def run(self):
        while True:
            self.check_and_clean()
            time.sleep(self.poll_time)


class UDPServer(BaseUDPServer):

    _server_type = 'TOU_UDP'

    _after_init = after_init

    def _load_handler(self):
        from ir.handler.tou import UDPHandler
        from ir.handler.tou import UDPMultiTransmitHandler

        self.UDPHandler = UDPHandler
        self.UDPMultiTransmitHandler = UDPMultiTransmitHandler

    def _init_socket(self):
        listen_addr = '127.0.0.1' if self._is_local else '0.0.0.0'
        listen_port = self._config['tou_listen_udp_port']
        if not listen_port:
            logging.error('[TOU-UDP] Invalid TOU config: tou_listen_udp_port')
            sys.exit(1)
        addr_info = socket.getaddrinfo(listen_addr, listen_port, 0,
                                       socket.SOCK_DGRAM, socket.SOL_UDP)
        if len(addr_info) == 0:
            logging.error(
                    '[TOU-UDP] failed to do getaddrinfo() for tou_udp_server')
            sys.exit(1)
        af, stype, proto, canname, sa = addr_info[0]
        sock = socket.socket(af, stype, proto)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setblocking(False)
        sock.bind(sa)
        logging.info(
                '[TOU-UDP] UDP server is listening at %s:%d' % (listen_addr,
                                                                listen_port)
                )
        return sock

    def _before_run(self):
        cryptor = Cryptor(self._config.get('cipher_name'),
                          self._config.get('passwd'),
                          self._config.get('crypto_libpath'),
                          reset_mode=True)
        logging.info('[TOU-UDP] Initialized Cryptor with cipher: %s' %\
                                            self._config.get('cipher_name'))
        self._excl = SrcExclusiveItems(self._is_local, cryptor)

        if (self._config.get('tou_udp_multi_remote') or
                self._config.get('udp_multi_source')):
            self._mth = self.UDPMultiTransmitHandler(self._config,
                                                     self._is_local)
            self._multi_transmit = True
            if not self._is_local:
                self._mkey_2_handler = {}
                self._available_saddrs = self._config.get('udp_multi_source')
            logging.info('[TOU-UDP] Multi-transmit on')
        else:
            self._multi_transmit = False

        max_idle_time = self._config.get('udp_socket_max_idle_time') or 60
        cleaner = ExpiredUDPSocketCleaner(self, max_idle_time)
        cleaner.start()

    def _local_server_socket_recv(self):
        data, src = self._server_sock.recvfrom(UDP_BUFFER_SIZE)
        port = self._config['tou_remote_tcp_port']
        dest = ('127.0.0.1', port)
        return data, src, dest
