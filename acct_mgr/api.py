# -*- coding: utf-8 -*-
#
# Copyright (C) 2005 Matthew Good <trac@matt-good.net>
#
# "THE BEER-WARE LICENSE" (Revision 42):
# <trac@matt-good.net> wrote this file.  As long as you retain this notice you
# can do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return.   Matthew Good
#
# Author: Matthew Good <trac@matt-good.net>

from trac.core import *
from trac.config import Option, ExtensionOption

class IPasswordStore(Interface):
    """An interface for Components that provide a storage method for users and
    passwords.
    """

    def config_key(self):
        """
        '''Deprecated''': new implementations of this interface are not required
        to implement this method, since the prefered way to configure the
        `IPasswordStore` implemenation is by using its class name in
        the `password_store` option.

        Returns a string used to identify this implementation in the config.
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
        Returns True if a new account was created, False if an existing account
        was updated.
        """

    def check_password(self, user, password):
        """Checks if the password is valid for the user.
        """

    def delete_user(self, user):
        """Deletes the user account.
        Returns True if the account existed and was deleted, False otherwise.
        """

class IAccountChangeListener(Interface):
    """An interface for receiving account change events.
    """

    def user_created(self, user, password):
        """New user
        """

    def user_password_changed(self, user, password):
        """Password changed
        """

    def user_deleted(self, user):
        """User deleted
        """

class AccountManager(Component):
    """The AccountManager component handles all user account management methods
    provided by the IPasswordStore interface.

    The methods will be handled by the underlying password storage
    implementation set in trac.ini with the "account-manager.password_format"
    setting.
    """

    implements(IAccountChangeListener)

    _password_store = ExtensionOption('account-manager', 'password_store',
                                      IPasswordStore)
    _password_format = Option('account-manager', 'password_format')
    stores = ExtensionPoint(IPasswordStore)
    change_listeners = ExtensionPoint(IAccountChangeListener)

    # Public API

    def get_users(self):
        return self.password_store.get_users()

    def has_user(self, user):
        return self.password_store.has_user(user)

    def set_password(self, user, password):
        if self.password_store.set_password(user, password):
            self._notify('created', user, password)
        else:
            self._notify('password_changed', user, password)

    def check_password(self, user, password):
        return self.password_store.check_password(user, password)

    def delete_user(self, user):
        db = self.env.get_db_cnx() 
        cursor = db.cursor() 
        # Delete session attributes 
        cursor.execute("DELETE FROM session_attribute where sid=%s", (user,)) 
        # Delete session 
        cursor.execute("DELETE FROM session where sid=%s", (user,)) 
        # Delete any custom permissions set for the user 
        cursor.execute("DELETE FROM permission where username=%s", (user,)) 
        db.commit()
        db.close()
        # Delete from password store 
        self.log.debug('deleted user')
        if self.password_store.delete_user(user):
            self._notify('deleted', user)

    def supports(self, operation):
        try:
            store = self.password_store
        except AttributeError:
            return False
        else:
            return hasattr(store, operation)

    def password_store(self):
        try:
            return self._password_store
        except AttributeError:
            # fall back on old "password_format" option
            fmt = self._password_format
            for store in self.stores:
                config_key = getattr(store, 'config_key', None)
                if config_key is None:
                    continue
                if config_key() == fmt:
                    return store
            # if the "password_format" is not set re-raise the AttributeError
            raise
    password_store = property(password_store)

    def _notify(self, func, *args):
        func = 'user_' + func
        for l in self.change_listeners:
            getattr(l, func)(*args)

    # IAccountChangeListener methods

    def user_created(self, user, password):
        self.log.info('Created new user: %s' % user)

    def user_password_changed(self, user, password):
        self.log.info('Updated password for user: %s' % user)

    def user_deleted(self, user):
        self.log.info('Deleted user: %s' % user)

