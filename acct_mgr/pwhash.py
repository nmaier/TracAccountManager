# -*- coding: utf8 -*-
#
# Copyright (C) 2007 Matthew Good <trac@matt-good.net>
#
# "THE BEER-WARE LICENSE" (Revision 42):
# <trac@matt-good.net> wrote this file.  As long as you retain this notice you
# can do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return.   Matthew Good
#
# Author: Matthew Good <trac@matt-good.net>

from binascii import hexlify
import md5, sha

from trac.core import *
from trac.config import Option

from md5crypt import md5crypt

class IPasswordHashMethod(Interface):
    def generate_hash(user, password):
        pass

    def test_hash(user, password, hash):
        pass


class HtPasswdHashMethod(Component):
    implements(IPasswordHashMethod)

    def generate_hash(self, user, password):
        password = password.encode('utf-8')
        return htpasswd(password)

    def check_hash(self, user, password, hash):
        password = password.encode('utf-8')
        hash2 = htpasswd(password, hash)
        print password, hash, hash2
        return hash == hash2


class HtDigestHashMethod(Component):
    implements(IPasswordHashMethod)

    realm = Option('account-manager', 'htdigest_realm')

    def generate_hash(self, user, password):
        user,password,realm = _encode(user, password, self.realm)
        return ':'.join([realm, htdigest(user, realm, password)])

    def check_hash(self, user, password, hash):
        user,password,realm = _encode(user, password, self.realm)
        return hash == self.generate_hash(user, password)


def _encode(*args):
    return [a.encode('utf-8') for a in args]

# check for the availability of the "crypt" module for checking passwords on
# Unix-like platforms
# MD5 is still used when adding/updating passwords
try:
    from crypt import crypt
except ImportError:
    crypt = None

# os.urandom was added in Python 2.4
# try to fall back on reading from /dev/urandom on older Python versions
try:
    from os import urandom
except ImportError:
    from random import randrange
    def urandom(n):
        return ''.join([chr(randrange(256)) for _ in xrange(n)])

def salt():
    s = ''
    v = long(hexlify(urandom(4)), 16)
    itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    for i in range(8):
        s += itoa64[v & 0x3f]; v >>= 6
    return s

def htpasswd(password, salt_=None):
# TODO need unit test of generating new hash
    if salt_ is None:
        salt_ = salt()
        if crypt is None:
            salt_ = '$apr1$' + salt_
    print 'htpasswd', password, salt_, crypt(password, salt_)
    if salt_.startswith('$apr1$'):
        return md5crypt(password, salt_[6:].split('$')[0], '$apr1$')
    elif salt_.startswith('{SHA}'):
        return '{SHA}' + sha.new(password).digest().encode('base64')[:-1]
    elif crypt is None:
        # crypt passwords are only supported on Unix-like systems
        raise NotImplementedError('The "crypt" module is unavailable '
                                  'on this platform.')
    else:
        return crypt(password, salt_)

def htdigest(user, realm, password):
    p = ':'.join([user, realm, password])
    return md5.new(p).hexdigest()
