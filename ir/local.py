#!/usr/bin/python3.6
# coding: utf-8


from ir.server.base import TCPServer, UDPServer


__all__ = ['LocalTCPServer', 'LocalUDPServer']


class LocalTCPServer(TCPServer):

    _is_local = True


class LocalUDPServer(UDPServer):

    _is_local = True
