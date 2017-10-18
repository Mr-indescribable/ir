#!/usr/bin/python3.6
# coding: utf-8


from ir.server import base, tou


class TCPServer(base.TCPServer):

    _is_local = False


class UDPServer(base.UDPServer):

    _is_local = False


class TOUTCPServer(tou.TCPServer):

    _is_local = False


class TOUUDPServer(tou.UDPServer):

    _is_local = False
