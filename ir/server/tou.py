#!/usr/bin/python3.6
#coding: utf-8

from ir.server.base import TCPServer as BaseTCPServer
from ir.server.base import UDPServer as BaseUDPServer


__all__ = ['TCPServer', 'UDPServer']


class TCPServer(BaseTCPServer):
    pass


class UDPServer(BaseUDPServer):
    pass
