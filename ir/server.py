#!/usr/bin/python3.6
# coding: utf-8

import errno
import logging
import select
import socket
import time
from threading import Thread

from ir import tools
from ir.handler import TCPHandler, UDPHandler, UDPMultiTransmitHandler
from ir.crypto import Cryptor, preload_crypto_lib
from ir.protocol import IVManager, PacketParser


__all__ = ['TCPServer',
           'UDPServer',
           'ExpiredUDPSocketCleaner',
           'SrcExclusiveItems']
 

POLL_TIMEOUT = 4

IP_TRANSPARENT = 19
IP_RECVORIGDSTADDR = 20

UDP_BUFFER_SIZE = 65536


class ServerMixin(object):

    # mark the server type
    _is_local = False

    def __init__(self, config_path):
        self._config = self._read_config(config_path)
        self._local_sock = self._init_socket()
        self._local_sock_fd = self._local_sock.fileno()
        self._epoll = select.epoll()
        self._epoll.register(self._local_sock_fd, self._poll_mode)

    def _read_config(self, config_path):
        return tools.Initer.init_from_config_file(config_path)

    def _add_handler(self, fd, handler):
        # in tcp mode, a handler will have multiple fd
        # in udp mode, handlers only have the client_socket's fd
        self._fd_2_handler[fd] = handler

    def _remove_handler(self, fd):
        del self._fd_2_handler[fd]

    def _before_run(self):
        pass

    def _after_run(self):
        pass

    def run(self):
        preload_crypto_lib(self._config.get('cipher_name'),
                           self._config.get('crypto_libpath'))
        self._before_run()
        self.__running = True
        try:
            while self.__running:
                events = self._epoll.poll(POLL_TIMEOUT)
                logging.debug('got event from epoll: %s' % str(events))
                for fd, evt in events:
                    self.handle_event(fd, evt)
        except KeyboardInterrupt:
            self.shutdown()
        self._after_run()

    def shutdown(self):
        self.__running = False


class TCPServer(ServerMixin):

    _poll_mode = select.EPOLLIN | select.EPOLLRDHUP | select.EPOLLERR

    # store tcp connection handlers, {fd: handler}
    _fd_2_handler = {}

    def _before_run(self):
        # initialize a iv_cryptor with default iv
        self._iv_cryptor = Cryptor(self._config.get('cipher_name'),
                                   self._config.get('passwd'),
                                   self._config.get('crypto_libpath'),
                                   reset_mode=True)
        logging.info('[TCP] Initialized cipher with method: %s'\
                                    % self._config.get('cipher_name'))

    def _init_socket(self, listen_addr=None, listen_port=None, so_backlog=1024):
        listen_addr = listen_addr or self._config['listen_addr']
        listen_port = listen_port or self._config['listen_tcp_port']
        addr_info = socket.getaddrinfo(listen_addr, listen_port, 0,
                                       socket.SOCK_STREAM, socket.SOL_TCP)
        af, stype, proto, canname, sa = addr_info[0]
        sock = socket.socket(af, stype, proto)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        sock.setblocking(False)
        sock.bind(sa)
        sock.listen(so_backlog)
        logging.info('[TCP] Server is listening at %s:%d' % (
                                    self._config['listen_addr'],
                                    self._config['listen_tcp_port']))
        return sock

    def handle_event(self, fd, evt):
        handler = self._fd_2_handler.get(fd)
        if fd == self._local_sock_fd and not handler:
            try:
                conn, src = self._local_sock.accept()
                logging.info('[TCP] Accepted connection from %s:%d, fd: %d' %\
                                                        (*src, conn.fileno()))
                TCPHandler(self, conn, src, self._epoll,
                           self._config, self._is_local)
            except (OSError, IOError) as e:
                error_no = tools.errno_from_exception(e)
                if error_no in (errno.EAGAIN, errno.EINPROGRESS,
                                errno.EWOULDBLOCK):
                    return
        else:
            handler = self._fd_2_handler.get(fd)
            if handler:
                handler.handle_event(fd, evt)
            else:
                logging.warn('[TCP] fd removed')


class UDPServer(ServerMixin):

    _poll_mode = select.EPOLLIN | select.EPOLLERR

    # store udp relay handlers, {fd: handler}
    _fd_2_handler = {}

    # store udp relay handlers, {'saddr:sport@daddr:dport': handler}
    _key_2_handler = {}

    default_iv_changed = False

    def _add_handler(self, handler, fd=None, src_port=None):
        if fd:
            self._fd_2_handler[fd] = handler
        if src_port:
            self._src_port_2_handler[src_port] = handler

    def _remove_handler(self, fd=None, key=None, src_port=None):
        if fd in self._fd_2_handler:
            del self._fd_2_handler[fd]
        if key in self._key_2_handler:
            del self._key_2_handler[key]
        if (hasattr(self, '_src_port_2_handler') and
                src_port in self._src_port_2_handler):
            del self._src_port_2_handler[src_port]

    def _init_socket(self, listen_addr=None, listen_port=None):
        listen_addr = listen_addr or self._config['listen_addr']
        listen_port = listen_port or self._config['listen_udp_port']
        addr_info = socket.getaddrinfo(listen_addr, listen_port, 0,
                                       socket.SOCK_DGRAM, socket.SOL_UDP)
        af, stype, proto, canname, sa = addr_info[0]
        sock = socket.socket(af, stype, proto)
        if self._is_local:
            sock.setsockopt(socket.SOL_IP, IP_RECVORIGDSTADDR, 1)
            sock.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
        sock.setblocking(False)
        sock.bind(sa)
        logging.info('[UDP] Server is listening at %s:%d' % (
                                    self._config['listen_addr'],
                                    self._config['listen_udp_port']))
        return sock

    def _before_run(self):
        cryptor = Cryptor(self._config.get('cipher_name'),
                          self._config.get('passwd'),
                          self._config.get('crypto_libpath'),
                          reset_mode=True)
        logging.info('[UDP] Initialized cipher with method: %s'\
                                    % self._config.get('cipher_name'))
        self._excl = SrcExclusiveItems(self._is_local, cryptor)

        if (self._config.get('udp_multi_remote') or
                self._config.get('udp_multi_source')):
            self._mth = UDPMultiTransmitHandler(self._config, self._is_local)
            self._multi_transmit = True
            if not self._is_local:
                self._src_port_2_handler = {}
                self._available_saddrs = self._config.get('udp_multi_source')
            logging.info('[UDP] Multi-transmit on')
        else:
            self._multi_transmit = False

        max_idle_time = self._config.get('udp_socket_max_idle_time') or 60
        cleaner = ExpiredUDPSocketCleaner(self, max_idle_time)
        cleaner.start()

    def _gen_handler_key(self, source, dest):
        return '%s:%d@%s:%d' % (source[0], source[1], dest[0], dest[1])

    def _local_manage_iv(self, iv, decrypted_by_nc=None):
        cmd = self._excl.iv_mgr_new_stage(iv, decrypted_by_nc)
        if cmd == self._excl.Cmd.RESET:
            logging.warn('[IV_MNG] IV change fialed, reset SrcExclusiveItems')
            self._excl.reset()
        if cmd == self._excl.Cmd.SEND_IV:
            logging.info('[IV_MNG] Sending new iv to server')
            cryptor = Cryptor(self._config.get('cipher_name'),
                              self._config.get('passwd'),
                              self._config.get('crypto_libpath'),
                              iv=iv,
                              reset_mode=True)
            self._excl.nc_in_progress = cryptor
            self._excl.current_cryptor = cryptor
            if self._excl.new_cryptor_a:
                self._excl.new_cryptor_b = cryptor
                self._excl.old_cryptor = self._excl.new_cryptor_a
            else:
                self._excl.new_cryptor_a = cryptor
                self._excl.old_cryptor = self._excl._default_cryptor
        if cmd == self._excl.Cmd.SEND_EMPTY_IV:
            logging.info('[IV_MNG] Received confirmation from server')
        if cmd == self._excl.Cmd.DROP_OLD:
            self._excl.new_cryptor_a = self._excl.nc_in_progress
            self._excl.current_cryptor = self._excl.new_cryptor_a
            self._excl.nc_in_progress = None
            self._excl.new_cryptor_b = None
            logging.info('[IV_MNG] Cryptor successfully updated')

    def _remote_manage_iv(self, src_af, iv, decrypted_by_nc):
        cmd = self._excl.iv_mgr_new_stage(iv, decrypted_by_nc)
        if cmd == self._excl.Cmd.RESET:
            logging.warn('[IV_MNG] Reset SrcExclusiveItems for %s' % src_af[0])
            self._excl.reset()
        if cmd == self._excl.Cmd.DO_CONFIRM:
            logging.info('[IV_MNG] Confirm iv change for %s' % src_af[0])
            cryptor = Cryptor(self._config.get('cipher_name'),
                              self._config.get('passwd'),
                              self._config.get('crypto_libpath'),
                              iv=iv,
                              reset_mode=True)
            self._excl.nc_in_progress = cryptor
            self._excl.current_cryptor = cryptor
            if not self._excl.new_cryptor_a:
                self._excl.new_cryptor_a = cryptor
                self._excl.old_cryptor = self._excl._default_cryptor
            else:
                self._excl.new_cryptor_b = cryptor
                self._excl.old_cryptor = self._excl.new_cryptor_a
        if cmd == self._excl.Cmd.DROP_OLD_AND_SEND_EMPTY_IV:
            self._excl.new_cryptor_a = self._excl.nc_in_progress
            self._excl.current_cryptor = self._excl.new_cryptor_a
            self._excl.nc_in_progress = None
            self._excl.new_cryptor_b = None
            logging.info('[IV_MNG] Updated cryptor for %s' % src_af[0])

    def _server_socket_recv(self):
        if self._is_local:
            data, anc, f, src = self._local_sock.recvmsg(UDP_BUFFER_SIZE,
                                                         socket.CMSG_SPACE(24))
            sock_opt = tools.unpack_sockopt(anc[0][2])
            dest = ('.'.join([str(u) for u in sock_opt[2:]]), sock_opt[1])
            return data, src, dest
        else:
            data, src = self._local_sock.recvfrom(UDP_BUFFER_SIZE)
            cryptor = self._excl.current_cryptor
            res = PacketParser.parse_udp_packet(cryptor, data)
            if not res['valid']:
                err_msg = '[UDP] Got invalid packet from %s:%d' % src
                if not (self._excl.old_cryptor and cryptor != self._excl.old_cryptor):
                    logging.info(err_msg)
                    return None, None, None
                cryptor = self._excl.old_cryptor
                res = PacketParser.parse_udp_packet(cryptor, data)
                if not res['valid']:
                    cryptor = self._excl._default_cryptor
                    res = PacketParser.parse_udp_packet(cryptor, data)
                    if not res['valid']:
                        logging.info(err_msg)
                        return None, None, None

            if self._multi_transmit:
                res, is_duplicate = self._mth.handle_recv(res)
                if is_duplicate:
                    logging.debug('[UDP_MT] Dropped duplicate packet')
                    return None, src, res['dest_af']

            # local lost the iv
            if (res['iv'] and cryptor == self._excl._default_cryptor and
                self._excl.current_cryptor != self._excl._default_cryptor and
                self._excl.old_cryptor != self._excl._default_cryptor):
                self._excl.reset()

            decrypted_by_nc = cryptor == self._excl.nc_in_progress
            self._remote_manage_iv(src, res['iv'], decrypted_by_nc)
            return res['data'], src, res['dest_af']
        return None, None, None

    def handle_event(self, fd, evt):
        if fd == self._local_sock_fd:
            if evt & select.EPOLLERR:
                logging.warn('[UDP] Server socket got EPOLLERR')
            elif evt & select.EPOLLIN:
                data, src, dest = self._server_socket_recv()
                if not dest:
                    return

                if self._multi_transmit and not self._is_local:
                    if src[0] not in self._available_saddrs:
                        logging.info(
                                '[UDP] Got request from unavailable source')
                        return

                    handler = self._src_port_2_handler.get(src[1])
                    if not (handler and handler.update_last_call_time()):
                        handler = UDPHandler(src, dest, self, self._local_sock,
                                             self._epoll, self._config,
                                             self._is_local)
                    if data:
                        handler.handle_local_recv(data)
                    else:
                        handler.one_more_src(src)
                else:
                    key = self._gen_handler_key(src, dest)
                    handler = self._key_2_handler.get(key)
                    if not (handler and handler.update_last_call_time()):
                        handler = UDPHandler(src, dest, self, self._local_sock,
                                             self._epoll, self._config,
                                             self._is_local, key)
                        self._key_2_handler[key] = handler
                    handler.handle_local_recv(data)
        else:
            if evt & select.EPOLLERR:
                logging.warn('[UDP] Client socket got EPOLLERR')
            elif evt & select.EPOLLIN:
                handler = self._fd_2_handler.get(fd)
                if handler:
                    # In most situation, upd_socket_max_idle_time will be
                    # a long time, such as 1 minute. It's vary rare that
                    # a udp response takes 1 minute. If it happened, just
                    # drop the packet.
                    if not handler.update_last_call_time():
                        logging.info(
                                '[UDP] Response timeout, handler destroyed')
                        return
                    handler.handle_remote_resp()
                else:
                    logging.warn('[UDP] fd removed')


class ExpiredUDPSocketCleaner(Thread):

    def __init__(self, server, max_idle_time, poll_time=3):
        Thread.__init__(self, daemon=True)
        self._server = server
        self.max_idle_time = max_idle_time
        self.poll_time = poll_time

    def check_and_clean(self):
        now = time.time()
        fds = list(self._server._fd_2_handler.keys())
        handlers = list(self._server._fd_2_handler.values())
        for fd, handler in zip(fds, handlers):
            if now - handler.last_call_time > self.max_idle_time:
                if handler.destroyed:
                    self._server._remove_handler(fd)
                else:
                    handler.destroy()

    def run(self):
        while True:
            self.check_and_clean()
            time.sleep(self.poll_time)


class SrcExclusiveItems():

    def __init__(self, is_local, default_cryptor=None):
        self._is_local = is_local
        self.iv_mgr = IVManager(is_local)
        self._default_cryptor = default_cryptor
        self.current_cryptor = default_cryptor
        self.new_cryptor_a = None
        self.new_cryptor_b = None
        self.nc_in_progress = None
        self.old_cryptor = None
        self.todo = None

    def iv_mgr_new_stage(self, iv, decrypted_by_nc=None):
        cmd = self.iv_mgr.new_stage(iv, decrypted_by_nc)
        if cmd != self.Cmd.TRANSMIT:
            self.todo = cmd
        return cmd

    def reset(self):
        self.iv_mgr = IVManager(self._is_local)
        self.current_cryptor = self._default_cryptor
        self.new_cryptor_a = None
        self.new_cryptor_b = None
        self.nc_in_progress = None
        self.old_cryptor = None
        self.todo = None

    @property
    def Cmd(self):
        return self.iv_mgr.Cmd

    @property
    def iv(self):
        return self.iv_mgr._iv

    @property
    def stage(self):
        return self.iv_mgr.stage

    @property
    def Stages(self):
        return self.iv_mgr.Stages
