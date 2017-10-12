#!/usr/bin/python3.6
# coding: utf-8


from ir.server.base import TCPServer, UDPServer


__all__ = ['RemoteTCPServer', 'RemoteUDPServer']


class RemoteTCPServer(TCPServer):

    _is_local = False


class RemoteUDPServer(UDPServer):

    _is_local = False
