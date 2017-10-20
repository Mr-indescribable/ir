#!/usr/bin/python3.6
#coding: utf-8

from ir.handler.base import TCPHandler as BaseTCPHandler
from ir.handler.base import UDPHandler as BaseUDPHandler
from ir.protocol.tou import PacketMaker as TOUPacketMaker
from ir.protocol.tou import PacketParser as TOUPacketParser


__all__ = ['TCPHandler', 'UDPHandler']


UP_STREAM_BUF_SIZE = 16384
DOWN_STREAM_BUF_SIZE = 32768
UDP_BUFFER_SIZE = 65536


class TCPHandler(BaseTCPHandler):

    '''
    In TCP over UDP mode, the TCPHandler won't encrypt the data.
    It just send data to the UDP server.
    Then the UDP server will encrypt these data before transmit.
    '''

    def __init__(self, server, epoll, config, is_local, src, local_sock=None):
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
            self._remote_ip = self._config.get('remote_addr')
            self._remote_port = self._config.get('remote_tcp_port')
            self._remote_af = (self._remote_ip, self._remote_port)
            self._dest_af = None
        else:
            self._remote_ip = None
            self._remote_port = None
            self._remote_af = None
        events = select.EPOLLIN | select.EPOLLRDHUP | select.EPOLLERR
        self._add_sock_to_poll(self._local_sock, events)
        if self._is_local:
            self._handle_fpacket()
            self._fpacket_handled = True
        self._local_sock_poll_mode = 'ro'
        self._remote_sock_poll_mode = 'ro'

    def _handle_fpacket(self, data=b''):
        if self._is_local:
            self._dest_af = self._local_get_dest_af()

    def _on_local_read(self):
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


class UDPHandler(BaseUDPHandler):
    pass
