# -*- coding: utf8 -*-
#
# Copyright (C) 2005 Matthew Good <trac@matt-good.net>
#
# "THE BEER-WARE LICENSE" (Revision 42):
# <trac@matt-good.net> wrote this file.  As long as you retain this notice you
# can do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return.   Matthew Good
#
# Author: Matthew Good <trac@matt-good.net>

from binascii import hexlify
import errno
import md5, sha
import os.path
import fileinput
from md5crypt import md5crypt

from trac.core import *
from trac.config import Option

from api import IPasswordStore

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


class _RelativePathOption(Option):
 
    def __get__(self, instance, owner):
        if instance is None:
            return self
        path = super(_RelativePathOption, self).__get__(instance, owner)
        return os.path.normpath(os.path.join(instance.env.path, path))


class AbstractPasswordFileStore(Component):
    """Base class for managing password files such as Apache's htpasswd and
    htdigest formats.

    See the concrete sub-classes for usage information.
    """

    filename = _RelativePathOption('account-manager', 'password_file')

    def has_user(self, user):
        return user in self.get_users()

    def get_users(self):
        filename = self.filename
        if not os.path.exists(filename):
            return []
        return self._get_users(filename)

    def set_password(self, user, password):
        user = user.encode('utf-8')
        password = password.encode('utf-8')
        return not self._update_file(self.prefix(user),
                                     self.userline(user, password))

    def delete_user(self, user):
        user = user.encode('utf-8')
        return self._update_file(self.prefix(user), None)

    def check_password(self, user, password):
        filename = self.filename
        if not os.path.exists(filename):
            return False
        prefix = self.prefix(user.encode('utf-8'))
        password = password.encode('utf-8')
        fd = file(filename)
        try:
            for line in fd:
                if line.startswith(prefix):
                    return self._check_userline(password, prefix,
                                                line[len(prefix):-1])
        finally:
            fd.close()
        return False

    def _update_file(self, prefix, userline):
        """If `userline` is empty the line starting with `prefix` is 
        removed from the user file.  Otherwise the line starting with `prefix`
        is updated to `userline`.  If no line starts with `prefix` the
        `userline` is appended to the file.

        Returns `True` if a line matching `prefix` was updated,
        `False` otherwise.
        """
        filename = self.filename
        matched = False
        try:
            for line in fileinput.input(str(filename), inplace=True):
                if line.startswith(prefix):
                    if not matched and userline:
                        print userline
                    matched = True
                else:
                    print line,
        except EnvironmentError, e:
            if e.errno == errno.ENOENT:
                pass # ignore when file doesn't exist and create it below
            elif e.errno == errno.EACCES:
                raise TracError('The password file could not be updated.  '
                                'Trac requires read and write access to both '
                                'the password file and its parent directory.')
            else:
                raise
        if not matched and userline:
            f = open(filename, 'a')
            try:
                print >>f, userline
            finally:
                f.close()
        return matched


def salt():
    s = ''
    v = long(hexlify(urandom(4)), 16)
    itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    for i in range(8):
        s += itoa64[v & 0x3f]; v >>= 6
    return s


class HtPasswdStore(AbstractPasswordFileStore):
    """Manages user accounts stored in Apache's htpasswd format.

    To use this implementation add the following configuration section to
    trac.ini:
    {{{
    [account-manager]
    password_store = HtPasswdStore
    password_file = /path/to/trac.htpasswd
    }}}
    """

    implements(IPasswordStore)

    def config_key(self):
        return 'htpasswd'

    def prefix(self, user):
        return user + ':'

    def userline(self, user, password):
        if crypt is None:
            return self.prefix(user) + md5crypt(password, salt(), '$apr1$')
        else:
            return self.prefix(user) + crypt(password, salt())

    def _check_userline(self, password, prefix, suffix):
        if suffix.startswith('$apr1$'):
            return suffix == md5crypt(password, suffix[6:].split('$')[0],
                                      '$apr1$')
        elif suffix.startswith('{SHA}'):
            return (suffix[5:] ==
                    sha.new(password).digest().encode('base64')[:-1])
        elif crypt is None:
            # crypt passwords are only supported on Unix-like systems
            raise NotImplementedError('The "crypt" module is unavailable '
                                      'on this platform.  Only MD5 '
                                      'passwords (starting with "$apr1$") '
                                      'are supported in the htpasswd file.')
        else:
            return suffix == crypt(password, suffix)

    def _get_users(self, filename):
        f = open(filename)
        for line in f:
            user = line.split(':', 1)[0]
            if user:
                yield user.decode('utf-8')


class HtDigestStore(AbstractPasswordFileStore):
    """Manages user accounts stored in Apache's htdigest format.

    To use this implementation add the following configuration section to
    trac.ini:
    {{{
    [account-manager]
    password_store = HtDigestStore
    password_file = /path/to/trac.htdigest
    htdigest_realm = TracDigestRealm
    }}}
    """


    implements(IPasswordStore)

    realm = Option('account-manager', 'htdigest_realm')

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
        _realm = self.realm
        f = open(filename)
        for line in f:
            args = line.split(':')[:2]
            if len(args) == 2:
                user, realm = args
                if realm == _realm and user:
                    yield user.decode('utf-8')

