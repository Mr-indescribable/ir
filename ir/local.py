#!/usr/bin/python3.6
# coding: utf-8


from ir.server import TCPServer, UDPServer


__all__ = ['LocalTCPServer', 'LocalUDPServer']


class LocalTCPServer(TCPServer):

    _is_local = True


class LocalUDPServer(UDPServer):

    _is_local = True


def test_tcp(config_path='../example/local_config.example.json'):
    server = LocalTCPServer(config_path)
    server.run()


def test_udp(config_path='../example/local_config.example.json'):
    server = LocalUDPServer(config_path)
    server.run()

def test_conf(config_path='../example/local_config.example.json'):
    server = LocalUDPServer(config_path)
    print(type(server._config))
    import json
    print(json.dumps(server._config, indent=4))
    multi = server._config.get('udp_multi_remote')
    print(multi)
    for ip, port in multi.items():
        print(ip, port)

if __name__ == '__main__':
    test_udp()
