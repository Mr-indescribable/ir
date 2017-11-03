#!/usr/bin/python3.6
#coding: utf-8

import sys
import select
import socket
import logging

from ir.handler.base import CacheQueue
from ir.handler.base import TCPHandler as BaseTCPHandler
from ir.handler.base import UDPHandler as BaseUDPHandler
from ir.handler.base import UDPMultiTransmitHandler as BaseMTH
from ir.protocol.tou import PacketMaker as TOUPacketMaker
from ir.protocol.tou import PacketParser as TOUPacketParser
from ir.protocol.tou import TOUAdapter


__all__ = ['TCPHandler', 'UDPHandler']


UP_STREAM_BUF_SIZE = 16384
DOWN_STREAM_BUF_SIZE = 32768
UDP_BUFFER_SIZE = 65536


class TCPHandler(BaseTCPHandler):

    '''
    In TCP over UDP mode, the TCPHandler won't encrypt the data.
    It just send data to the UDP server.
    Then the UDP server will encrypt these data before transmit it.

    And now, TCPHandlers at local side only have local_sock,
    And of course, TCPHandlers at remote side only have remote_sock
    '''

    def __init__(self, server, epoll, config, arq_repeater,
                       is_local, src, local_sock=None):
        self._server = server
        self._local_sock = local_sock
        if self._local_sock:
            self._local_sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
            self._local_sock.setblocking(False)
        self._src = src
        self._epoll = epoll
        self._config = config
        self._is_local = is_local
        self._data_2_local = []
        self._data_2_remote = []
        self._remote_af = None
        self._remote_sock = None
        self._remote_connected = False
        self._fpacket_handled = False
        self._waiting_for_destroy = False
        self._tcp_destroyed = False
        self._udp_destroyed = False
        # This one is in order to be compatible with the base TCPHandler
        self._destroyed = self._tcp_destroyed

        if self._is_local:
            events = select.EPOLLIN | select.EPOLLRDHUP
            self._add_sock_to_poll(self._local_sock, events)
            self._tou_adapter = TOUAdapter(arq_repeater, self._config,
                                           self._is_local, src)
            self._add_sock_to_poll(self._tou_adapter._udp_sock, select.EPOLLIN)
        else:
            self._tou_adapter = TOUAdapter(arq_repeater, self._config,
                                           self._is_local, src,
                                           self._server.server_sock)

        if self._is_local:
            self._dest_af = self._local_get_dest_af()
            self._tou_adapter.connect(self._dest_af)
            self._fpacket_handled = True
        self._local_sock_poll_mode = 'ro'
        self._remote_sock_poll_mode = 'ro'

    def _fd_2_sock(self, fd):
        if self._is_local:
            if self._local_sock and fd == self._local_sock.fileno():
                return self._local_sock
            if fd == self._tou_adapter.udp_fd:
                return self._tou_adapter._udp_sock
        else:
            if self._remote_sock and fd == self._remote_sock.fileno():
                return self._remote_sock
            if fd == self._server.server_fd:
                return self._server.server_sock
        return None

    # In TOU mode, _on_local_read will only be invoked at local side
    def _on_local_read(self):
        if self._tcp_destroyed:
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
            logging.info('[TCP] Got null data from local socket')
            return

        if self._remote_connected:
            self._tou_adapter.tcp_in(data)
        else:
            self._data_2_remote.append(data)

    # In TOU mode, _on_remote_read will only be invoked at remote side
    def _on_remote_read(self):
        if self._tcp_destroyed:
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
            logging.info('[TCP] Got null data from remote socket')
            return

        self._tou_adapter.tcp_in(data)

    # remote only
    def _on_remote_connected(self):
        self._remote_connected = True
        self._epoll_modify_2_ro(self._remote_sock)
        self._tou_adapter.feedback_conn_completed()

    # local only
    def _on_local_disconnect(self):
        if self._data_2_remote:
            data = b''.join(self._data_2_remote)
            self._data_2_remote = []
            self._tou_adapter.tcp_in(data)
        if not self._data_2_remote:
            logging.info('[TCP] Local socket got EPOLLRDHUP, do destroy()')
            self.destroy_tcp_sock()

    # remote only
    def _on_remote_disconnect(self):
        # at remote side, there is no buffered data in _data_2_local now
        logging.info('[TCP] Remote socket got EPOLLRDHUP, do destroy()')
        self.destroy_tcp_sock()

    def _on_local_error(self):
        logging.warn('[TCP] Local socket got EPOLLERR, do destroy()')
        self.destroy_tcp_sock()

    def _on_remote_error(self):
        logging.warn('[TCP] Remote socket got EPOLLERR, do destroy()')
        self.destroy_tcp_sock()

    def _on_udp_in(self, data=None):
        if self._udp_destroyed:
            return

        cmd, param = self._tou_adapter.on_udp_in(data)

        if cmd == 'connect' and not self._fpacket_handled:
            # Then command "connect" only appears at the remote side
            # when the local side requests a connection
            self._remote_af = param
            self._remote_sock = self._create_remote_sock(self._remote_af)
            evts = select.EPOLLIN | select.EPOLLOUT | select.EPOLLRDHUP
            self._add_sock_to_poll(self._remote_sock, evts)
            self._fpacket_handled = True
        elif cmd == 'connected':
            # The command "connected" only appears at local side when the
            # remote side connected to destination server.
            self._remote_connected = True
            data = b''.join(self._data_2_remote)
            self._data_2_remote = []
            self._tou_adapter.tcp_in(data)
        elif cmd == 'disconnect':
            if not self._tcp_destroyed:
                self.destroy_tcp_sock()
        elif cmd == 'transmit':
            # The command "transmit" means that we received a data block
            # from the TCP stream, we need to write it into the tcp socket
            if not self._tcp_destroyed:
                data = param
                if self._is_local:
                    self._data_2_local.append(data)
                    if self._local_sock_poll_mode == 'ro':
                        self._epoll_modify_2_rw(self._local_sock)
                else:
                    self._data_2_remote.append(data)
                    if self._remote_sock_poll_mode == 'ro':
                        self._epoll_modify_2_rw(self._remote_sock)
        elif cmd == 'destroy':
            # The command "destroy" means that the data transmission has
            # been finished, we can destroy this handler now
            self.destroy_tou_adapter()
        elif cmd == 'wait_for_destroy':
            # The command "wait_for_destroy" only appears at the
            # passive disconnecting side. It means that this side has finished
            # its data transmission, but the proactive side may not know this.
            # The way to make sure the proactive side know this is to response
            # the packets from proactive side. Once it stop sending packets
            # from a period of time that we expected, then we can assert
            # the handler at proactive side has been destroyed. Then, we can
            # destroy the handler at the passive side
            self._waiting_for_destroy = True

    def _on_udp_error(self):
        # We need to keep the UDP socket work, at least it needs to complete
        # UDP disconnection. So, rebuild it if EPOLLERR happends.
        logging.info('[TOU] UDP socket got EPOLLERR, do rebuild')
        old_fd = self._tou_adapter.udp_fd
        self._server._remove_handler(old_fd)
        self._epoll.unregister(old_fd)

        self._tou_adapter.rebuild_udp_sock()
        self._add_sock_to_poll(self._tou_adapter._udp_sock, select.EPOLLIN)

    def handle_event(self, fd, evt, data=None):
        sock = self._fd_2_sock(fd)
        if not sock:
            logging.warn('[TOU] Unknow socket error')
            return

        # In TOU mode, local side only have local_sock and remote side only
        # have remote_sock. The other 2 sockets is the udp_sock in TOUAdapter
        if sock == self._tou_adapter._udp_sock:
            if self._udp_destroyed:
                logging.info('[TOU-UDP] Handler destroyed')
                return
            if evt & select.EPOLLERR:
                self._on_udp_error()
            if evt & (select.EPOLLIN):
                self._on_udp_in(data)
        else:
            if self._tcp_destroyed:
                logging.info('[TOU-TCP] TCPHandler destroyed')
                return
            if sock == self._remote_sock:
                if evt & select.EPOLLERR:
                    self._on_remote_error()
                if evt & (select.EPOLLIN):
                    self._on_remote_read()
                if evt & select.EPOLLOUT:
                    if not self._is_local and not self._remote_connected:
                        self._on_remote_connected()
                    else:
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

    def destroy_tcp_sock(self):
        if self._tcp_destroyed:
            logging.warn('[TOU-TCP] Socket already destroyed')
            return

        self._tou_adapter.on_tcp_destroyed()
        self._tcp_destroyed = True
        self._destroyed = True

        if self._is_local:
            self._data_2_local = []
            loc_fd = self._local_sock.fileno()
            self._server._remove_handler(loc_fd)
            self._epoll.unregister(loc_fd)
            self._local_sock.close()
            self._local_sock = None
            logging.debug('[TOU-TCP] Local socket destroyed, fd: %d' % loc_fd)
        elif not self._is_local and self._remote_sock:
            self._data_2_remote = []
            rmt_fd = self._remote_sock.fileno()
            self._server._remove_handler(rmt_fd)
            self._epoll.unregister(rmt_fd)
            self._remote_sock.close()
            self._remote_sock = None
            if self._is_local:
                af = self._dest_af
            else:
                af = self._remote_af
            logging.info('[TOU-TCP] Remote socket @ %s:%d destroyed, fd: %d' %\
                                                                  (*af, rmt_fd))

    def destroy_tou_adapter(self):
        if not self._tcp_destroyed:
            self.destroy_tcp_sock()

        if self._udp_destroyed:
            logging.warn('[TOU-UDP] Adapter already destroyed')
            return

        self._udp_destroyed = True
        udp_fd = self._tou_adapter.udp_fd
        if self._is_local:
            self._server._remove_handler(udp_fd)
            self._epoll.unregister(udp_fd)
        else:
            self._server._remove_handler(src_port=self._src[1])
        self._tou_adapter.destroy()
        self._tou_adapter = None

        if self._is_local:
            logging.debug('[TOU-UDP] Adapter destroyed, fd: %d' % udp_fd)
        else:
            logging.debug('[TOU-UDP] Adapter destroyed')

    @property
    def fb_last_recv_time(self):
        return self._tou_adapter.fb_last_recv_time

    @property
    def udp_socket_destroyed(self):
        return self._udp_destroyed


class UDPHandler(BaseUDPHandler):

    def _before_init(self):
        if self._is_local and not self._server._multi_transmit:
            remote_addr = self._config.get('remote_addr')
            remote_udp_port = self._config.get('tou_remote_udp_port')
            self._remote_af = (remote_addr, remote_udp_port)


class UDPMultiTransmitHandler(BaseMTH):

    def __init__(self, config, is_local):
        self._config = config
        self._is_local = is_local
        self._min_salt_len = config.get('udp_min_salt_len') or 4
        self._max_salt_len = config.get('udp_max_salt_len') or 32

        if self._is_local:
            multi_remote = config.get('tou_udp_multi_remote')
            if not isinstance(multi_remote, dict):
                raise Exception('Format of tou_udp_multi_remote is invalid')
            self._server_af_list = [(ip, pt) for ip, pt in multi_remote.items()]

        ms = config.get('udp_multi_transmit_max_packet_serial') or 32768
        self._max_serial = ms
        self._transmit_times = config.get('udp_multi_transmit_times') or 1
        self.serial = -1
        self._cache = CacheQueue()
