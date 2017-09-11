#!/usr/bin/python3.6
# coding: utf-8


from ir.server import TCPServer, UDPServer


__all__ = ['RemoteTCPServer', 'RemoteUDPServer']


class RemoteTCPServer(TCPServer):

    _is_local = False


class RemoteUDPServer(UDPServer):

    _is_local = False


def test_tcp(config_path='../example/remote_config.example.json'):
    server = RemoteTCPServer(config_path)
    server.run()


def test_udp(config_path='../example/remote_config.example.json'):
    server = RemoteUDPServer(config_path)
    server.run()


def test_conf(config_path='../example/remote_config.example.json'):
    server = RemoteUDPServer(config_path)
    print(type(server._config))
    print(server._config)


if __name__ == '__main__':
    test_udp()
