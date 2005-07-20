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

import inspect

from trac.core import *

class IPasswordStore(Interface):
    """An interface for Components that provide a storage method for users and
    passwords.
    """

    def config_key(self):
        """Returns a string used to identify this implementation in the config.
        This password storage implementation will be used if the value of
        the config property "account-manager.password_format" matches.
        """

    def get_users(self):
        """Returns an iterable of the known usernames
        """

    def has_user(self, user):
        """Returns whether the user account exists.
        """

    def set_password(self, user, password):
        """Sets the password for the user.  This should create the user account
        if it doesn't already exist.
        """

    def delete_user(self, user):
        """Deletes the user account.
        """

# os.urandom was added in Python 2.4
# try to fall back on reading from /dev/urandom on older Python versions
try:
    from os import urandom
except ImportError:
    def urandom(n):
        return open('/dev/urandom').read(n)

class AccountManager(Component):
    """The AccountManager component handles all user account management methods
    provided by the IPasswordStore interface.

    The methods will be handled by the underlying password storage
    implementation set in trac.ini with the "account-manager.password_format"
    setting.
    """

    stores = ExtensionPoint(IPasswordStore)

    def _dispatch(self, func):
        return getattr(self._get_store(), func)

    def _get_store(self):
        fmt = self.config.get('account-manager', 'password_format')
        for store in self.stores:
            if store.config_key() == fmt:
                return store


class DispatchProperty(object):
    def __init__(self, name, fget):
        self.name = name
        self.fget = fget

    def __get__(self, obj, objtype=None):
        if obj is None:
            return self
        return self.fget(obj, self.name)

# Add the IPasswordStore methods to the AccountManager to dispatch to the
# active implementation
for func, v in inspect.getmembers(IPasswordStore, inspect.ismethod):
    setattr(AccountManager, func, DispatchProperty(func, AccountManager._dispatch))


