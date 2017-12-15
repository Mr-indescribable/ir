#!/usr/bin/python3.6
#coding: utf-8

import sys
import time
import select
import socket
import logging
from threading import Thread

from ir.crypto import Cryptor
from ir.server.base import SrcExclusiveItems
from ir.server.base import TCPServer as BaseTCPServer
from ir.server.base import UDPServer as BaseUDPServer
from ir.protocol.tou import CtrlPacketParser, ARQRepeater
from ir.protocol.tou_consts import *


__all__ = ['TCPServer', 'UDPServer', 'TOUUDPSocketCleaner']


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

        min_rpt_times = self._config.get('tou_arq_min_repeat_times', 10)
        max_rpt_times = self._config.get('tou_arq_max_repeat_times', 20)
        self._arq_repeater = ARQRepeater(min_rpt_times, max_rpt_times)
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
            '[TOU-TCP] TCP Server is listening at '
            '%s:%d' % (listen_addr, listen_port)
        )
        return sock

    def _local_handle_event(self, fd, evt):
        handler = self._fd_2_handler.get(fd)
        if fd == self._server_sock_fd and not handler:
            try:
                local_sock, src = self._server_sock.accept()
                c_fd = local_sock.fileno()
                logging.info(
                    '[TOU-TCP] Accepted connection from %s:%d, '
                    'fd: %d' % (*src, c_fd)
                )
                self.TCPHandler(
                    self, self._epoll, self._config, self._arq_repeater,
                    self._is_local, src, local_sock
                )
            except (OSError, IOError) as e:
                eno = tools.errno_from_exception(e)
                if eno in (errno.EAGAIN, errno.EINPROGRESS, errno.EWOULDBLOCK):
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
        handler = self.TCPHandler(
                      self, self._epoll, self._config, self._arq_repeater,
                      self._is_local, src, None
                  )
        self._udp_src_port_2_handler[src[1]] = handler
        return handler

    def remote_reset_handler(self, handler, evt, data, src):
        if not handler.tcp_destroyed:
            handler.destroy_tcp_sock()
        if not handler.udp_destroyed:
            handler.destroy_tou_adapter()

        handler = self._remote_new_handler(src)
        handler.handle_event(self._server_sock_fd, evt, data)
        logging.warn('[TOU-TCP] Reseted TCPHandler for src_port %d' % src[1])

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
            src_ports = list(self._server._udp_src_port_2_handler.keys())
            handlers = list(self._server._udp_src_port_2_handler.values())
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

    _csp_2_handler = {}    # csp ==> client_sock_port, works at remote side
    _sp_2_handler = {}     # sp ==> source_port, works at local side

    _after_init = after_init

    def __init__(self, config_path):
        self._before_init()
        self._config = self._read_config(config_path)
        self._load_handler()
        self._server_sock, self._ctrl_sock = self._init_socket()
        self._server_sock_fd = self._server_sock.fileno()
        self._ctrl_sock_fd = self._ctrl_sock.fileno()
        self._epoll = select.epoll()
        self._epoll.register(self._server_sock_fd, self._poll_mode)
        self._epoll.register(self._ctrl_sock_fd, self._poll_mode)
        self._after_init()

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
        addr_info = socket.getaddrinfo(
                        listen_addr, listen_port, 0,
                        socket.SOCK_DGRAM, socket.SOL_UDP
                    )
        if len(addr_info) == 0:
            logging.error(
                '[TOU-UDP] failed to do getaddrinfo() for tou_udp_server'
            )
            sys.exit(1)
        af, stype, proto, canname, sa = addr_info[0]
        server_sock = socket.socket(af, stype, proto)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.setblocking(False)
        server_sock.bind(sa)
        logging.info(
            '[TOU-UDP] UDP server is listening at '
            '%s:%d' % (listen_addr, listen_port)
        )

        listen_addr = '127.0.0.1'
        listen_port = self._config['tou_udp_ctrl_port']
        ctrl_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ctrl_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ctrl_sock.setblocking(False)
        ctrl_sock.bind((listen_addr, listen_port))
        logging.info(
            '[TOU-UDP] UDP server control socket is listening at '
            '%s:%d' % (listen_addr, listen_port)
        )
        
        return server_sock, ctrl_sock

    def _before_run(self):
        cryptor = Cryptor(self._config.get('cipher_name'),
                          self._config.get('passwd'),
                          self._config.get('crypto_libpath'),
                          reset_mode=True)
        logging.info(
            '[TOU-UDP] Initialized Cryptor with cipher: '
            '%s' % self._config.get('cipher_name')
        )
        self._excl = SrcExclusiveItems(self._is_local, cryptor)

        if (self._config.get('tou_udp_multi_remote') or
                self._config.get('udp_multi_source')):
            self._mth = self.UDPMultiTransmitHandler(
                            self._config, self._is_local
                        )
            self._multi_transmit = True
            if not self._is_local:
                self._mkey_2_handler = {}
                self._available_saddrs = self._config.get('udp_multi_source')
            logging.info('[TOU-UDP] Multi-transmit on')
        else:
            self._multi_transmit = False

    def _local_server_socket_recv(self):
        data, src = self._server_sock.recvfrom(UDP_BUFFER_SIZE)
        port = self._config['tou_remote_tcp_port']
        dest = ('127.0.0.1', port)
        return data, src, dest

    def _tou_remove_handler_cache(self, sp=None, csp=None):
        if self._is_local and sp in self._sp_2_handler:
            del self._sp_2_handler[sp]
        elif not self._is_local and csp in self._csp_2_handler:
            del self._csp_2_handler[csp]

    def _tou_destroy_handler(self, sp=None, csp=None):
        if self._is_local:
            handler = self._sp_2_handler.get(sp)
            self._tou_remove_handler_cache(sp=sp)
        else:
            handler = self._csp_2_handler.get(csp)
            self._tou_remove_handler_cache(csp=csp)
        if handler:
            handler.destroy()

    def handle_event(self, fd, evt):
        if fd == self._ctrl_sock_fd:
            data, src = self._ctrl_sock.recvfrom(UDP_BUFFER_SIZE)
            type_, param = CtrlPacketParser.parse_ctrl_packet(data)

            if type_ == CTRL_TYPE_0_SIG_DESTROY_HANDLER:
                if self._is_local:
                    self._tou_destroy_handler(sp=src[1])
                else:
                    self._tou_destroy_handler(csp=param['csp'])
        elif fd == self._server_sock_fd:
            if evt & select.EPOLLERR:
                logging.warn('[UDP] Server socket got EPOLLERR')
                return
            elif evt & select.EPOLLIN:
                data, src, dest = self._server_socket_recv()
                if not dest:
                    return

                if self._multi_transmit and not self._is_local:
                    if src[0] not in self._available_saddrs:
                        logging.info(
                            '[UDP] Got request from unavailable source'
                        )
                        return

                    mkey = self._gen_handler_mkey(src, dest)
                    handler = self._mkey_2_handler.get(mkey)
                    if not (handler and handler.update_last_call_time()):
                        handler = self.UDPHandler(
                                      src, dest, self, self._server_sock,
                                      self._epoll, self._config,
                                      self._is_local, mkey=mkey
                                  )
                    if data:
                        handler.handle_local_recv(data)
                    else:
                        handler.one_more_src(src)
                else:
                    key = self._gen_handler_key(src, dest)
                    handler = self._key_2_handler.get(key)
                    if not (handler and handler.update_last_call_time()):
                        handler = self.UDPHandler(
                                      src, dest, self, self._server_sock,
                                      self._epoll, self._config,
                                      self._is_local, key
                                  )
                        self._key_2_handler[key] = handler
                    handler.handle_local_recv(data)
        else:
            if evt & select.EPOLLERR:
                logging.warn('[UDP] Client socket got EPOLLERR')
                return
            elif evt & select.EPOLLIN:
                handler = self._fd_2_handler.get(fd)
                if handler:
                    # In most situation, upd_socket_max_idle_time will be
                    # a long time, such as 1 minute. It's vary rare that
                    # a udp response takes 1 minute. If it happened, just
                    # drop the packet.
                    if not handler.update_last_call_time():
                        logging.info(
                            '[UDP] Response timeout, handler destroyed'
                        )
                        return
                    handler.handle_remote_resp()
                else:
                    logging.warn('[UDP] fd removed')
