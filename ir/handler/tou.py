#!/usr/bin/python3.6
#coding: utf-8

from ir.handler.base import TCPHandler as BaseTCPHandler
from ir.handler.base import UDPHandler as BaseUDPHandler


__all__ = ['TCPHandler', 'UDPHandler']


class TCPHandler(BaseTCPHandler):
    pass


class UDPHandler(BaseUDPHandler):
    pass
