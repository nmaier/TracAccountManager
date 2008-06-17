# -*- coding: utf8 -*-
#
# Copyright (C) 2005,2006,2007 Matthew Good <trac@matt-good.net>
#
# "THE BEER-WARE LICENSE" (Revision 42):
# <trac@matt-good.net> wrote this file.  As long as you retain this notice you
# can do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return.   Matthew Good
#
# Author: Matthew Good <trac@matt-good.net>

import errno
import os.path
import fileinput

from trac.core import *
from trac.config import Option

from api import IPasswordStore
from pwhash import htpasswd, htdigest
from util import EnvRelativePathOption


class AbstractPasswordFileStore(Component):
    """Base class for managing password files such as Apache's htpasswd and
    htdigest formats.

    See the concrete sub-classes for usage information.
    """

    filename = EnvRelativePathOption('account-manager', 'password_file')

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
        user = user.encode('utf-8')
        password = password.encode('utf-8')
        prefix = self.prefix(user)
        fd = file(filename)
        try:
            for line in fd:
                if line.startswith(prefix):
                    return self._check_userline(user, password,
                                                line[len(prefix):].rstrip('\n'))
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
                elif line.endswith('\n'):
                    print line,
                else: # make sure the last line has a newline
                    print line
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
        return self.prefix(user) + htpasswd(password)

    def _check_userline(self, user, password, suffix):
        return suffix == htpasswd(password, suffix)

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
        return self.prefix(user) + htdigest(user, self.realm, password)

    def _check_userline(self, user, password, suffix):
        return suffix == htdigest(user, self.realm, password)

    def _get_users(self, filename):
        _realm = self.realm
        f = open(filename)
        for line in f:
            args = line.split(':')[:2]
            if len(args) == 2:
                user, realm = args
                if realm == _realm and user:
                    yield user.decode('utf-8')

