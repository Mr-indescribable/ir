#!/usr/bin/python3.6
# coding: utf-8

import os
import errno
import logging
import random
import select
import socket
import struct
import time

from ir import tools
from ir.crypto import Cryptor
from ir.protocol.base import PacketMaker, PacketParser


__all__ = ['TCPHandler',
           'UDPHandler',
           'UDPMultiTransmitHandler',
           'CacheQueue']


SO_ADDR_SIZE = 16
SO_ORIGINAL_DST = 80

UP_STREAM_BUF_SIZE = 16384
DOWN_STREAM_BUF_SIZE = 32768
UDP_BUFFER_SIZE = 65536


class TCPHandler():

    def __init__(self, server, local_sock, src, epoll, config, is_local):
        self._server = server
        self._local_sock = local_sock
        self._local_sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        self._local_sock.setblocking(False)
        self._src = src
        self._epoll = epoll
        self._config = config
        self._is_local = is_local
        self._data_2_local_sock = []
        self._data_2_remote_sock = []
        self._remote_sock = None
        self._fpacket_handled = False
        self._destroyed = False
        if self._is_local:
            self._iv_len = self._config.get('iv_len') or 32
            self._iv = os.urandom(self._iv_len)
            self._remote_ip = self._config.get('remote_addr')
            self._remote_port = self._config.get('remote_tcp_port')
            self._remote_af = (self._remote_ip, self._remote_port)
            self._dest_af = None
            self._cryptor = Cryptor(self._config.get('cipher_name'),
                                    self._config.get('passwd'),
                                    self._config.get('crypto_libpath'),
                                    self._iv)
        else:
            self._remote_ip = None
            self._remote_port = None
            self._remote_af = None
            self._cryptor = None
        events = select.EPOLLIN | select.EPOLLRDHUP | select.EPOLLERR
        self._add_sock_to_poll(self._local_sock, events)
        if self._is_local:
            self._handle_fpacket()
            self._fpacket_handled = True
        self._local_sock_poll_mode = 'ro'
        self._remote_sock_poll_mode = 'ro'

    def _fd_2_sock(self, fd):
        if fd == self._local_sock.fileno():
            return self._local_sock
        if self._remote_sock and self._remote_sock.fileno() == fd:
            return self._remote_sock
        return None

    def _add_sock_to_poll(self, sock, mode):
        self._epoll.register(sock.fileno(), mode)
        self._server._add_handler(sock.fileno(), self)

    def _local_get_dest_af(self):
        opt = self._local_sock.getsockopt(socket.SOL_IP,
                                          SO_ORIGINAL_DST,
                                          SO_ADDR_SIZE)
        dest_info = tools.unpack_sockopt(opt)[1:]
        port = dest_info[0]
        ip = '.'.join([str(u) for u in dest_info[1:]])
        return (ip, port)

    def _create_remote_sock(self, remote_af):
        remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        remote_sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        remote_sock.setblocking(False)
        remote_sock.bind(('0.0.0.0', 0))
        try:
            remote_sock.connect(remote_af)
        except (OSError, IOError) as e:
            if tools.errno_from_exception(e) == errno.EINPROGRESS:
                pass
            else:
                return None
        logging.debug('[TCP] Created remote socket @ %s:%d, fd: %d' %\
                                        (*remote_af, remote_sock.fileno()))
        return remote_sock

    def _epoll_modify_2_ro(self, sock):
        events = select.EPOLLIN | select.EPOLLRDHUP | select.EPOLLERR
        self._epoll.modify(sock.fileno(), events)
        if sock == self._local_sock:
            self._local_sock_poll_mode = 'ro'
        elif sock == self._remote_sock:
            self._remote_sock_poll_mode = 'ro'

    def _epoll_modify_2_rw(self, sock):
        events = select.EPOLLIN | select.EPOLLOUT |\
                    select.EPOLLRDHUP | select.EPOLLERR
        self._epoll.modify(sock.fileno(), events)
        if sock == self._local_sock:
            self._local_sock_poll_mode = 'rw'
        elif sock == self._remote_sock:
            self._remote_sock_poll_mode = 'rw'

    def _write_to_sock(self, data, sock):
        # This function is copied from
        #      shadowsocks.tcprelay.TCPRelayHandler._write_to_sock
        # I made some change to fit my project.

        # Copyright 2013-2015 clowwindy
        # Licensed under the Apache License, Version 2.0
        # https://www.apache.org/licenses/LICENSE-2.0

        if not data or not sock:
            return None
        uncomplete = False
        try:
            l = len(data)
            s = sock.send(data)
            if s < l:
                data = data[s:]
                uncomplete = True
        except (OSError, IOError) as e:
            if tools.errno_from_exception(e) in (errno.EAGAIN, errno.EINPROGRESS,
                                                 errno.EWOULDBLOCK):
                uncomplete = True
            else:
                self.destroy()
                return None
        if uncomplete:
            if sock == self._local_sock:
                self._data_2_local_sock.append(data)
            elif sock == self._remote_sock:
                self._data_2_remote_sock.append(data)
        else:
            self._epoll_modify_2_ro(sock)

    def _on_local_read(self):
        # This functuion is copied from
        #      shadowsocks.tcprelay.TCPRelayHandler._on_local_read
        # I made some change to fit my project.

        # Copyright 2013-2015 clowwindy
        # Licensed under the Apache License, Version 2.0
        # https://www.apache.org/licenses/LICENSE-2.0

        if self._destroyed:
            return

        if self._is_local:
            buf_size = UP_STREAM_BUF_SIZE
        else:
            buf_size = DOWN_STREAM_BUF_SIZE
        try:
            data = self._local_sock.recv(buf_size)
        except (OSError, IOError) as e:
            if tools.errno_from_exception(e) in (errno.ETIMEDOUT, errno.EAGAIN,
                                                 errno.EWOULDBLOCK):
                return
        if not data:
            logging.info('[TCP] Local socket got null data')
            return

        if self._is_local:
            data = self._cryptor.encrypt(data)
        else:
            if not self._fpacket_handled:
                self._handle_fpacket(data)
                self._fpacket_handled = True
                return
            else:
                data = self._cryptor.decrypt(data)
        self._data_2_remote_sock.append(data)
        logging.debug(
                '[TCP] %dB to %s:%d, stored' % (len(data), *self._remote_af))
        if self._remote_sock_poll_mode == 'ro':
            self._epoll_modify_2_rw(self._remote_sock)

    def _on_remote_write(self):
        # This function is copied from
        #      shadowsocks.tcprelay.TCPRelayHandler._on_remote_write
        # I made some change to fit my project.

        # Copyright 2013-2015 clowwindy
        # Licensed under the Apache License, Version 2.0
        # https://www.apache.org/licenses/LICENSE-2.0

        if self._destroyed:
            return

        if self._data_2_remote_sock:
            data = b''.join(self._data_2_remote_sock)
            self._data_2_remote_sock = []
            self._write_to_sock(data, self._remote_sock)
            logging.debug(
                    '[TCP] Sent %dB to %s:%d' % (len(data), *self._remote_af))

    def _on_remote_read(self):
        # This function is copied from
        #      shadowsocks.tcprelay.TCPRelayHandler._on_remote_read
        # I made some change to fit my project.

        # Copyright 2013-2015 clowwindy
        # Licensed under the Apache License, Version 2.0
        # https://www.apache.org/licenses/LICENSE-2.0

        if self._destroyed:
            return
        if self._is_local:
            buf_size = UP_STREAM_BUF_SIZE
        else:
            buf_size = DOWN_STREAM_BUF_SIZE

        data = None
        try:
            data = self._remote_sock.recv(buf_size)
        except (OSError, IOError) as e:
            if tools.errno_from_exception(e) in (errno.ETIMEDOUT, errno.EAGAIN,
                                                 errno.EWOULDBLOCK):
                return
        if not data:
            logging.info('[TCP] Remote socket got null data')
            return

        if self._is_local:
            data = self._cryptor.decrypt(data)
        else:
            data = self._cryptor.encrypt(data)
        self._data_2_local_sock.append(data)
        logging.debug('[TCP] %dB to %s:%d, stored' % (len(data), *self._src))
        if self._local_sock_poll_mode == 'ro':
            self._epoll_modify_2_rw(self._local_sock)

    def _on_local_write(self):
        # This function is copied from
        #      shadowsocks.tcprelay.TCPRelayHandler._on_local_write
        # I made some change to fit my project.

        # Copyright 2013-2015 clowwindy
        # Licensed under the Apache License, Version 2.0
        # https://www.apache.org/licenses/LICENSE-2.0

        if self._destroyed:
            return

        if self._data_2_local_sock:
            data = b''.join(self._data_2_local_sock)
            self._data_2_local_sock = []
            self._write_to_sock(data, self._local_sock)
            logging.debug(
                    '[TCP] Sent %dB to %s:%d' % (len(data), *self._src))

    def _on_local_disconnect(self):
        if self._data_2_remote_sock:
            self._on_remote_write()
        if not self._data_2_remote_sock:
            logging.info('[TCP] Local socket got EPOLLRDHUP, do destroy()')
            self.destroy()

    def _on_remote_disconnect(self):
        if self._data_2_local_sock:
            self._on_local_write()
        if not self._data_2_local_sock:
            logging.info('[TCP] Remote socket got EPOLLRDHUP, do destroy()')
            self.destroy()

    def _on_local_error(self):
        logging.warn('[TCP] Local socket got EPOLLERR, do destroy()')
        self.destroy()

    def _on_remote_error(self):
        logging.warn('[TCP] Remote socket got EPOLLERR, do destroy()')
        self.destroy()

    def _handle_fpacket(self, data=b''):
        if self._is_local:
            self._dest_af = self._local_get_dest_af()
            data = PacketMaker.make_tcp_fpacket(
                                            data, self._dest_af,
                                            self._iv, self._cryptor,
                                            self._server._iv_cryptor
                                            )
        else:
            res = PacketParser.parse_tcp_fpacket(
                                            data,
                                            self._server._iv_cryptor,
                                            self._config
                                            )
            if not res['valid']:
                logging.info(
                        '[TCP] Got invalid data from %s:%d' % self._src)
                self.destroy()
                return
            data = res['data']
            self._remote_af = res['dest_af']
            self._remote_ip = self._remote_af[0]
            self._remote_port = self._remote_af[1]
            self._cryptor = res['cryptor']
            self._iv = res['iv']
        if data:
            events = select.EPOLLIN | select.EPOLLOUT |\
                        select.EPOLLRDHUP | select.EPOLLERR
            self._data_2_remote_sock.append(data)
            logging.debug('[TCP] %dB to %s:%d, stored' % (len(data),
                                                          *self._remote_af))
        else:
            events = select.EPOLLIN | select.EPOLLRDHUP | select.EPOLLERR

        if self._is_local:
            if not (self._remote_ip and self._remote_port):
                raise ValueError(
                        "Invalid configuration: remote_addr/remote_tcp_port")
        else:
            if not (self._remote_ip and self._remote_port):
                logging.info("[TCP] Got invalid dest info, do destroy")
                self.destroy()
                return

        self._remote_sock = self._create_remote_sock(self._remote_af)
        if not self._remote_sock:
            logging.warn('[TCP] Cannot connect to %s:%d, do destroy' %\
                                                         self._remote_af)
            self.destroy()
            return
        if self._is_local:
            logging.info('[TCP] Connecting to %s:%d' % self._dest_af)
        else:
            logging.info('[TCP] Connecting to %s:%d' % self._remote_af)

        self._add_sock_to_poll(self._remote_sock, events)

    def handle_event(self, fd, evt):
        if self._destroyed:
            logging.info('[TCP] Handler destroyed')
            return
        sock = self._fd_2_sock(fd)
        if not sock:
            logging.warn('[TCP] Unknow socket error, do destroy()')
            return

        if sock == self._remote_sock:
            if evt & select.EPOLLERR:
                self._on_remote_error()
            if evt & (select.EPOLLIN):
                self._on_remote_read()
            if evt & select.EPOLLOUT:
                self._on_remote_write()
            if evt & select.EPOLLRDHUP:
                self._on_remote_disconnect()
        elif sock == self._local_sock:
            if evt & select.EPOLLERR:
                self._on_local_error()
            if evt & (select.EPOLLIN):
                self._on_local_read()
            if evt & select.EPOLLOUT:
                self._on_local_write()
            if evt & select.EPOLLRDHUP:
                self._on_local_disconnect()

    def destroy(self):
        if self._destroyed:
            logging.warn('[TCP] Handler already destroyed')
            return

        self._destroyed = True
        loc_fd = self._local_sock.fileno()
        self._server._remove_handler(loc_fd)
        self._epoll.unregister(loc_fd)
        self._local_sock.close()
        self._local_sock = None
        logging.debug('[TCP] Local socket destroyed, fd: %d' % loc_fd)
        if hasattr(self, '_remote_sock') and self._remote_sock:
            rmt_fd = self._remote_sock.fileno()
            self._server._remove_handler(rmt_fd)
            self._epoll.unregister(rmt_fd)
            self._remote_sock.close()
            self._remote_sock = None
            if self._is_local:
                af = self._dest_af
            else:
                af = self._remote_af
            logging.info('[TCP] Remote socket @ %s:%d destroyed, fd: %d' %\
                                                              (*af, rmt_fd))

    @property
    def destroyed(self):
        return self._destroyed


class UDPHandler():

    def __init__(self, src, dest, server, server_sock, epoll,
                       config, is_local, key=None, mkey=None):
        self.last_call_time = time.time()
        self._src = src
        self._dest = dest
        self._server = server
        self._server_sock = server_sock
        self._epoll = epoll
        self._config = config
        self._is_local = is_local
        self._key = key
        self._mkey = mkey
        self._min_salt_len = config.get('udp_min_salt_len') or 4
        self._max_salt_len = config.get('udp_max_salt_len') or 32
        if self._is_local:
            remote_addr = config.get('remote_addr')
            remote_port = config.get('remote_udp_port')
            if not (remote_addr and remote_port):
                logging.error('[UDP] Invalid remote udp server configuration')
                import sys
                sys.exit(1)
            self._remote_af = (remote_addr, remote_port)

        self._client_sock = self._create_client_sock()
        if not self._client_sock:
            self._destroyed = True
            return
        self._add_sock_to_poll(self._client_sock,
                               select.EPOLLIN | select.EPOLLERR)
        self._destroyed = False
        if self._is_local:
            self._return_sock = self._create_return_sock()
            self._iv_len = self._config.get('iv_len') or 32
            self._iv_change_rate = self._config.get('udp_iv_change_rate')

        if self._server._multi_transmit and not self._is_local:
            self._src_addrs = [src[0]]
            self._src_port = src[1]

    def _create_client_sock(self):
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        client_sock.setblocking(False)
        client_sock.bind(('0.0.0.0', 0))
        fd = client_sock.fileno()
        logging.debug('[UDP] created client socket fd: %d' % fd)
        return client_sock

    def _create_return_sock(self):
        rt_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rt_sock.setsockopt(socket.SOL_IP, socket.IP_TRANSPARENT, 1)
        rt_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        rt_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        rt_sock.setblocking(False)
        rt_sock.bind(self._dest)
        return rt_sock

    def _add_sock_to_poll(self, sock, mode):
        self._epoll.register(sock.fileno(), mode)
        self._server._add_handler(self, fd=sock.fileno())
        if self._mkey:
            self._server._add_handler(self, mkey=self._mkey)

    def update_last_call_time(self):
        if self._destroyed:
            return False
        self.last_call_time = time.time()
        return True

    def handle_local_recv(self, data):
        if self._is_local:
            excl = self._server._excl
            if excl.stage in (excl.Stages.EXPECT_NEW_IV, excl.Stages.DONE):
                if self._iv_change_rate:
                    max_ = int(1 / self._iv_change_rate)
                    if (not self._server.default_iv_changed or
                            random.randint(0, max_) == 1):
                        self._server.default_iv_changed = True
                        iv = os.urandom(self._iv_len)
                        self._server._local_manage_iv(iv)

            if excl.todo == excl.Cmd.SEND_IV:
                iv = excl.iv
                cryptor = excl.old_cryptor
            else:
                iv = b''
                if excl.stage in (excl.Stages.EXPECT_NEW_IV,
                                  excl.Stages.EXPECT_CONFIRM):
                    cryptor = excl.old_cryptor or excl._default_cryptor
                else:
                    cryptor = excl.current_cryptor

            if self._server._multi_transmit:
                serial = self._server._mth.next_serial()
                self._server._mth.handle_transmit(self._client_sock, data,
                                                  cryptor, self._dest, iv,
                                                  serial)
                return

            data = PacketMaker.make_udp_packet(cryptor, data, self._dest, iv)
            target = self._remote_af
        else:
            # The first step I handle server socket's EPOLLIN event is
            # UDPServer._server_sock_recv. So, I do decryption in
            # UDPServer._server_sock_recv
            target = self._dest
        self._client_sock.sendto(data, target)
        logging.debug('[UDP local_recv] Sent %dB to %s:%d' % (len(data),
                                                              *target))

    def handle_remote_resp(self):
        data, src = self._client_sock.recvfrom(UDP_BUFFER_SIZE)
        excl = self._server._excl
        if self._is_local:
            cryptor = excl.current_cryptor
            res = PacketParser.parse_udp_packet(cryptor, data)
            if not res['valid']:
                err_msg = '[UDP] Got invalid packet from %s:%d' % src
                if not (excl.old_cryptor and cryptor != excl.old_cryptor):
                    logging.info(err_msg)
                    return
                cryptor = excl.old_cryptor
                res = PacketParser.parse_udp_packet(cryptor, data)
                if not res['valid']:
                    logging.info(err_msg)
                    return

            if self._server._multi_transmit:
                res, is_duplicate = self._server._mth.handle_recv(res)
                if is_duplicate:
                    logging.debug('[UDP_MT] Dropped duplicate packet')
                    return
            decrypted_by_nc = cryptor == excl.nc_in_progress
            iv = res['iv']
            self._server._local_manage_iv(iv, decrypted_by_nc)
            self._return_sock.sendto(res['data'], self._src)
        else:
            if excl.todo == excl.Cmd.DO_CONFIRM:
                iv = excl.iv
                cryptor = excl.current_cryptor
            elif excl.todo == excl.Cmd.DROP_OLD_AND_SEND_EMPTY_IV:
                iv = b''
                cryptor = excl.current_cryptor
            else:    # cmd == TRANSMIT
                iv = b''
                if excl.stage == excl.Stages.EXPECT_EMPTY_IV:
                    cryptor = excl.old_cryptor or excl._default_cryptor
                else:
                    cryptor = excl.current_cryptor

            if self._server._multi_transmit:
                serial = self._server._mth.next_serial()
                af_list = [(addr, self._src_port) for addr in self._src_addrs]
                self._server._mth.handle_transmit(self._server_sock, data,
                                                  cryptor, self._dest, iv,
                                                  serial, af_list)
                return
            data = PacketMaker.make_udp_packet(cryptor, data, self._src, iv)
            self._server_sock.sendto(data, self._src)
        logging.debug(
                '[UDP remote_resp] Sent %dB to %s:%d' % (len(data), *self._src))

    def one_more_src(self, src):
        addr = src[0]
        if addr not in self._src_addrs:
            self._src_addrs.append(addr)

    def destroy(self):
        if self._destroyed:
            logging.warn('[UDP] Handler already destroyed')
            return False

        self._destroyed = True
        fd = None
        if hasattr(self, '_return_sock') and self._return_sock:
            self._return_sock.close()
            self._return_sock = None
        if hasattr(self, '_client_sock') and self._client_sock:
            fd = self._client_sock.fileno()
            self._epoll.unregister(fd)
            self._client_sock.close()
            self._client_sock = None
        if fd:
            self._server._remove_handler(fd=fd)
        if self._key:
            self._server._remove_handler(key=self._key)
        if self._mkey:
            self._server._remove_handler(mkey=self._mkey)
        logging.debug('[UDP] Handler destroyed')
        return True

    @property
    def destroyed(self):
        return self._destroyed


class UDPMultiTransmitHandler():

    def __init__(self, config, is_local):
        self._config = config
        self._is_local = is_local
        self._min_salt_len = config.get('udp_min_salt_len') or 4
        self._max_salt_len = config.get('udp_max_salt_len') or 32

        if self._is_local:
            multi_remote = config.get('udp_multi_remote')
            if not isinstance(multi_remote, dict):
                raise Exception('Format of udp_multi_remote is invalid')
            self._server_af_list = [(ip, pt) for ip, pt in multi_remote.items()]

        ms = config.get('udp_multi_transmit_max_packet_serial') or 32768
        self._max_serial = ms
        self._transmit_times = config.get('udp_multi_transmit_times') or 1
        self.serial = -1
        self._cache = CacheQueue()

    def next_serial(self):
        if self.serial == self._max_serial:
            self.serial = -1
        self.serial += 1
        return self.serial

    def handle_transmit(self, sock, data, cryptor, dest_af,
                              iv, serial, af_list=None):
        '''do udp multi-transmit

        :param sock: just the socket
        :param data: raw data for apps 
        :param cryptor: Cryptor instance
        :param dest_af: address and port of destination. structure: (ip, port)
        :param iv: iv to send, type: bytes
        :param serial: serial number of packet. type: int
        :param af_list: server address list,
                        use self._server_af_list instead if not provided.
                        structure: [(ip, port), (ip, port)]
        '''

        af_list = af_list or self._server_af_list
        time_ = int(time.time() * 10000000)
        salt_len = None
        last_salt_len = None
        for af in af_list:
            while salt_len == last_salt_len:
                salt_len = random.randint(self._min_salt_len,
                                          self._max_salt_len)
            last_salt_len = salt_len

            salt = os.urandom(salt_len)
            packet = PacketMaker.make_udp_packet(cryptor, data, dest_af, iv,
                                                 serial, time_, salt)
            for _ in range(self._transmit_times):
                sock.sendto(packet, af)
            logging.debug('[UDP_MT] sent %dB to %s:%d, times: %d' %\
                                (len(packet), *af, self._transmit_times))

    def handle_recv(self, packet):
        '''call this function after parsed a packet in multi-transmit mode

        :param packet: parse result of packet, type: dict
        :rtype: packet: dict, is_duplicate: boolean
        '''

        serial = packet['serial']
        digest = tools.HashTools.smd5(packet['data'])
        if self._cache.cached(serial, digest):
            return packet, True
        self._cache.append(serial, digest)
        return packet, False


class CacheQueue():

    def __init__(self):
        self._queue = {}

    def append(self, serial, digest):
        self._queue[serial] = digest

    def cached(self, serial, digest):
        if self._queue.get(serial) != digest:
            return False
        return True


def test_socket_bind_time_spent():
    # UDPHandler.handle_remote_resp中向应用程序的socket写入数据部分的处理
    # 曾使用过和ss-redir相同的方法，此处测试socket新建、绑定、关闭所用的时间。

    # 目前这部分的功能已经修改过了，每个UDPHandler配备有一个return_socket
    # 用于返回数据至应用程序的socket，无需重复制作。
    # 这个测试用的函数暂且留着。（也许有用

    def _bind():
        tmp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tmp_sock.setsockopt(socket.SOL_IP, socket.IP_TRANSPARENT, 1)
        tmp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tmp_sock.bind(('192.168.122.1', 53))
        tmp_sock.close()

    def _test(times):
        t0 = time.time()
        for i in range(0, times):
            _bind()
        t1 = time.time()
        return t1 - t0

    print('bind and close socket 1 time: time spent %f sec.' % _test(1))
    print('bind and close socket 10000 time: time spent %f sec.' % _test(10000))


if __name__ == '__main__':
    test_socket_bind_time_spent()
