#!/usr/bin/python3.6
#coding: utf-8

from ir.handler.base import TCPHandler as BaseTCPHandler
from ir.handler.base import UDPHandler as BaseUDPHandler
from ir.protocol.tou import PacketMaker as TOUPacketMaker
from ir.protocol.tou import PacketParser as TOUPacketParser
from ir.protocol import TOUAdapter


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

    def __init__(self, server, epoll, config, arq_repeater,
                       is_local, src, local_sock=None):
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
        self._waiting_for_destroy = False
        self._tcp_destroyed = False
        self._udp_destroyed = False
        self._destroyed = False

        if self._is_local:
            self._remote_ip = self._config.get('remote_addr')
            self._remote_tcp_port = self._config.get('tou_remote_tcp_port')
            self._remote_udp_port = self._config.get('tou_remote_udp_port')
            self._remote_af = (self._remote_ip, self._remote_port)
            self._dest_af = None
            events = select.EPOLLIN | select.EPOLLRDHUP | select.EPOLLERR
            self._add_sock_to_poll(self._local_sock, events)
        else:
            self._remote_ip = None
            self._remote_port = None
            self._remote_af = None

        self._tou_adapter = TOUAdapter(arq_repeater, self._config,
                                       self._is_local, src)
        self._add_sock_to_poll(self._tou_adapter._udp_sock,
                               select.EPOLLIN | select.EPOLLERR)

        if self._is_local:
            self._handle_fpacket()
            self._fpacket_handled = True
        self._local_sock_poll_mode = 'ro'
        self._remote_sock_poll_mode = 'ro'

    def _handle_fpacket(self, packet=None):
        if self._is_local:
            self._dest_af = self._local_get_dest_af()
            self._tou_adapter.connect(self._dest_af)
        else:
            cmd, parsed_pkt = self._tou_adapter.udp_in(packet)
            if cmd != 'connect':
                logging.warning('[TOU] Type of first packet is not 0')
                self._tou_adapter.disconnect()
                return
            else:
                dest_af = parsed_pkt['dest_af']
                self._remote_sock = self._create_remote_sock(dest_af)
                if not self._remote_sock:
                    logging.warn(
                          '[TCP] Cannot connect to %s:%d, do destroy' % dest_af)
                    self._tou_adapter.disconnect()

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
            logging.info('[TCP] Got null data from local socket')
            return

    def destroy_tcp_sock(self):
        if self._tcp_destroyed:
            logging.warn('[TOU] TCP socket already destroyed')
            return

        self._tcp_destroyed = True
        self._waiting_for_destroy = True

        if self._is_local:
            loc_fd = self._local_sock.fileno()
            self._server._remove_handler(loc_fd)
            self._epoll.unregister(loc_fd)
            self._local_sock.close()
            self._local_sock = None
            logging.debug('[TCP] Local socket destroyed, fd: %d' % loc_fd)
        elif (not self._is_local and self._remote_sock):
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

    def destroy_udp_sock(self):
        if self._udp_destroyed:
            logging.warn('[TOU] UDP socket already destroyed')
            return

        self._udp_destroyed = True
        udp_fd = self._tou_adapter._udp_sock.fileno()
        if self._is_local:
            self._server._remove_handler(udp_fd)
        else:
            self._server._remove_handler(udp_fd, self._src[1])
        self._epoll.unregister(udp_fd)
        self._tou_adapter.destroy()
        self._tou_adapter = None
        logging.debug('[TOU] UDP socket destroyed, fd: %d' % udp_fd)

    @property
    def fb_last_recv_time(self):
        return self._tou_adapter.fb_last_recv_time

    @property
    def udp_socket_destroyed(self):
        return self._udp_destroyed


class UDPHandler(BaseUDPHandler):
    pass
