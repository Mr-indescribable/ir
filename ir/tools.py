#!/usr/bin/python3.6
# coding: utf-8

import hashlib
import json
import struct
import logging


class Initer(object):

    @classmethod
    def init_from_config_file(cls, config_path):
        config = cls.read_config_file(config_path)
        cls.init_logger(config.get('log_level'))
        logging.info('loaded config from %s' % config_path)
        return config

    @classmethod
    def read_config_file(cls, config_path):
        with open(config_path, 'rb') as f:
            data = f.read().decode('utf-8')
            try:
                return json.loads(data)
            except ValueError as e:
                logging.error('format error in %s' % config_path)
                import sys
                sys.exit(1)

    @classmethod
    def init_logger(cls, lvl):
        logging.basicConfig(level=logging.INFO,
                            format='%(levelname)-s: %(message)s')
        lvl_map = {
                'debug': logging.DEBUG,
                'info': logging.INFO,
                'warn': logging.WARN,
                'warning': logging.WARN,
                'error': logging.ERROR
                }
        level = lvl_map.get(lvl)
        if not level:
            logging.info('got invalid log level, using logging.INFO')
            level = logging.INFO
        logging.getLogger('').handlers = []
        logging.basicConfig(level=level,
                            format='%(asctime)s %(levelname)-8s %(message)s',
                            datefmt='%H:%M:%S')


class HashTools(object):

    @classmethod
    def _hash(cls, method, data):
        if isinstance(data, str):
            data = data.encode('utf-8')

        m = getattr(hashlib, method)()
        m.update(data)
        return m.hexdigest()

    @classmethod
    def md5(cls, data):
        return cls._hash('md5', data)

    @classmethod
    def smd5(cls, data):
        return cls._hash('md5', data)[8:24]

    @classmethod
    def sha1(cls, data):
        return cls._hash('sha1', data)

    @classmethod
    def sha256(cls, data):
        return cls._hash('sha256', data)

    @classmethod
    def sha512(cls, data):
        return cls._hash('sha512', data)


def unpack_sockopt(opt):
    # only first 8 bytes in opt is usefull, opt[8:] is 0x0000....0000
    return struct.unpack('!HHBBBB', opt[:8])


# from tornado.util
def errno_from_exception(e):
    """Provides the errno from an Exception object.

    There are cases that the errno attribute was not set so we pull
    the errno out of the args but if someone instatiates an Exception
    without any args you will get a tuple error. So this function
    abstracts all that behavior to give you a safe way to get the
    errno.
    """

    if hasattr(e, 'errno'):
        return e.errno
    elif e.args:
        return e.args[0]
    else:
        return None
