#!/usr/bin/python3.6
# coding: utf-8

import logging

from ir.crypto.openssl import OpenSSLCryptor, load_libcrypto
from ir.tools import HashTools


openssl_ciphers = {cipher: OpenSSLCryptor for cipher in\
                                   OpenSSLCryptor.supported_ciphers}
supported_cipher = {}
supported_cipher.update(openssl_ciphers)

openssl_preload_func_map = {cipher: load_libcrypto for cipher in\
                                   OpenSSLCryptor.supported_ciphers}
preload_funcs = {}
preload_funcs.update(openssl_preload_func_map)


def preload_crypto_lib(cipher_name=None, libpath='libcrypto.so.1.1'):
    preload_func = preload_funcs.get(cipher_name)
    if not preload_func:
        raise Exception('unsupported cipher name')
    preload_func(libpath)


def passwd_2_key_and_iv(passwd):
    key = HashTools.sha512(passwd)
    iv = HashTools.sha256(key)
    return key.encode('utf-8'), iv.encode('utf-8')


class Cryptor(object):

    def __init__(self, cipher_name=None, passwd=None,
                 libpath='libcrypto.so.1.1', iv=None, reset_mode=False):
        self._cipher_name = cipher_name
        self._cipher_cls = supported_cipher.get(cipher_name)
        if not self._cipher_cls:
            raise Exception('unsupported cipher name')
        if not passwd:
            raise Exception('password not defined')
        if not iv:
            key, iv = passwd_2_key_and_iv(passwd)
        else:
            key, _ = passwd_2_key_and_iv(passwd)
        self._passwd = passwd
        self._key = key
        self._iv = iv
        self._reset_mode = reset_mode
        self._libpath = libpath
        self._init_ciphers()

    def _init_ciphers(self):
        self._cipher = self._cipher_cls(self._cipher_name, self._key,
                                        self._iv, 1, self._libpath)
        self._decipher = self._cipher_cls(self._cipher_name, self._key,
                                          self._iv, 0, self._libpath)

    def reset(self):
        self._cipher.reset()
        self._decipher.reset()

    def encrypt(self, data):
        r = self._cipher.update(data)
        if self._reset_mode:
            # This will cost about 14ms of additional time for each 1k packet.
            self.reset()
        return r

    def decrypt(self, data):
        r = self._decipher.update(data)
        if self._reset_mode:
            self.reset()
        return r
