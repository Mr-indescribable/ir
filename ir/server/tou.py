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
        tou_remote_tcp_pt = self._config.get('tou_remote_tcp_port')
        if not isinstance(tou_remote_udp_pt, int):
            _exit()
        if not isinstance(tou_remote_tcp_pt, int):
            _exit()


class TCPServer(BaseTCPServer):

    _server_type = 'TOU_TCP'

    _after_init = after_init

    def _remove_handler(self, fd, src_port=None):
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
        logging.info('[TOU] Running TCP server under TCP over UDP mode')

    def _init_socket(self, listen_port=None, so_backlog=1024):
        listen_addr = '127.0.0.1'
        listen_port = listen_port or self._config['tou_listen_tcp_port']

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
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setblocking(False)
            sock.bind((listen_addr, listen_port))

        logging.info(
                '[TOU] TCP Server is listening at %s:%d' % (listen_addr,
                                                            listen_port)
                )
        return sock

    def _local_handle_event(self, fd, evt):
        handler = self._fd_2_handler.get(fd)
        if fd == self._server_sock_fd and not handler:
            try:
                local_sock, src = self._server_sock.accept()
                logging.info('[TCP] Accepted connection from %s:%d, fd: %d' %\
                                                        (*src, conn.fileno()))
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
                logging.warn('[TCP] fd removed')

    def _remote_handle_event(self, fd, evt):
        if fd == self._server_sock_fd:    # UDP in
            data, src = self._server_sock.recvfrom(UDP_BUFFER_SIZE)
            src_port = src[1]
            handler = self._udp_src_port_2_handler.get(src_port)
            if not handler:
                handler = self.TCPHandler(self, self._epoll, self._config,
                                          self._arq_repeater, self._is_local,
                                          src, None)
                self._udp_src_port_2_handler[src_port] = handler
                # handler.handle_something
        else:   # TCP event
            handler = self._fd_2_handler.get(fd)
            if handler:
                handler.handle_event(fd, evt)
            else:
                logging.warn('[TCP] fd removed')

    def handle_event(self, fd, evt):
        if self._is_local:
            self._local_handle_event(fd, evt)
        else:
            self._remote_handle_event(fd, evt)


class TOUUDPSocketCleaner(Thread):

    def __init__(self, server, max_idle_time=4, poll_time=4):
        Thread.__init__(self, daemon=True)

        self._server = server
        self.max_idle_time = max_idle_time
        self.poll_time = poll_time

    def check_and_clean(self):
        now = time.time()
        fds = list(self._server._fd_2_handler.keys())
        handlers = list(self._server._fd_2_handler.values())
        for fd, handler in zip(fds, handlers):
            if handler._waiting_for_destroy:
                if now - handler.fb_last_recv_time > self.max_idle_time:
                    if handler.udp_socket_destroyed:
                        self._server._remove_handler(fd)
                    else:
                        handler.destroy_udp_sock()

    def run(self):
        while True:
            self.check_and_clean()
            time.sleep(self.poll_time)


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
        data, src = self._server_sock.recvfrom(UDP_BUFFER_SIZE)
        if self._is_local:
            port = self._config['tou_remote_tcp_port']
        else:
            port = self._config['tou_listen_tcp_port']
        dest = ('127.0.0.1', port)
        return data, src, dest
