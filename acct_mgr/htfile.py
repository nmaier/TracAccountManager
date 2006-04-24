# -*- coding: iso8859-1 -*-
#
# Copyright (C) 2005 Matthew Good <trac@matt-good.net>
#
# "THE BEER-WARE LICENSE" (Revision 42):
# <trac@matt-good.net> wrote this file.  As long as you retain this notice you
# can do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return.   Matthew Good
#
# Author: Matthew Good <trac@matt-good.net>

from __future__ import generators

from binascii import hexlify
import md5
import os.path
import fileinput
from md5crypt import md5crypt

from trac.core import *

from api import IPasswordStore

# os.urandom was added in Python 2.4
# try to fall back on reading from /dev/urandom on older Python versions
try:
    from os import urandom
except ImportError:
    def urandom(n):
        return open('/dev/urandom').read(n)


class AbstractPasswordFileStore(Component):
    """Base class for managing password files such as Apache's htpasswd and
    htdigest formats.

    See the concrete sub-classes for usage information.
    """

    def has_user(self, user):
        return user in self.get_users()

    def get_users(self):
        if not os.path.exists(self._get_filename()):
            return []
        return self._get_users(self._get_filename())

    def set_password(self, user, password):
        return not self._update_file(self.prefix(user),
                                     self.userline(user, password))

    def delete_user(self, user):
        return self._update_file(self.prefix(user), None)

    def check_password(self, user, password):
        filename = self._get_filename()
        if not os.path.exists(filename):
            return False
        prefix = self.prefix(user)
        fd = file(filename)
        try:
            for line in fd:
                if line.startswith(prefix):
                    return self._check_userline(password, prefix,
                                                line[len(prefix):-1])
        finally:
            fd.close()
        return False

    def _get_filename(self):
        return self.config.get('account-manager', 'password_file')

    def _update_file(self, prefix, userline):
        filename = self._get_filename()
        written = False
        if os.path.exists(filename):
            for line in fileinput.input(str(filename), inplace=True):
                if line.startswith(prefix):
                    if not written and userline:
                        print userline
                    written = True
                else:
                    print line,
        if userline:
            f = open(filename, 'a')
            try:
                print >>f, userline
            finally:
                f.close()
        return written


def salt():
    s = ''
    v = long(hexlify(urandom(4)), 16)
    itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    for i in range(8):
        s += itoa64[v & 0x3f]; v >>= 6
    return s


class HtPasswdStore(AbstractPasswordFileStore):
    """Manages user accounts stored in Apache's htpasswd format.

    To use this implementation add the following configuration section to trac.ini
    {{{
    [account-manager]
    password_format = htpasswd
    password_file = /path/to/trac.htpasswd
    }}}
    """

    implements(IPasswordStore)

    def config_key(self):
        return 'htpasswd'

    def prefix(self, user):
        return user + ':'

    def userline(self, user, password):
        return self.prefix(user) + md5crypt(password, salt(), '$apr1$')

    def _check_userline(self, password, prefix, suffix):
        if not suffix.startswith('$apr1$'):
            return False
        return suffix == md5crypt(password, suffix[6:].split('$')[0], '$apr1$')

    def _get_users(self, filename):
        f = open(filename)
        for line in f:
            user = line.split(':', 1)[0]
            if user:
                yield user


class HtDigestStore(AbstractPasswordFileStore):
    """Manages user accounts stored in Apache's htdigest format.

    To use this implementation add the following configuration section to trac.ini
    {{{
    [account-manager]
    password_format = htdigest
    password_file = /path/to/trac.htdigest
    htdigest_realm = TracDigestRealm
    }}}
    """


    implements(IPasswordStore)

    def __init__(self):
        self.realm = self.config.get('account-manager', 'htdigest_realm')

    def config_key(self):
        return 'htdigest'

    def prefix(self, user):
        return '%s:%s:' % (user, self.realm)

    def userline(self, user, password):
        p = self.prefix(user)
        return p + md5.new(p + password).hexdigest()

    def _check_userline(self, password, prefix, suffix):
        return suffix == md5.new(prefix + password).hexdigest()

    def _get_users(self, filename):
        f = open(filename)
        for line in f:
            args = line.split(':')[:2]
            if len(args) == 2:
                user, realm = args
                if realm == self.realm and user:
                    yield user

