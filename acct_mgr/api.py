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
from trac.config import Option, BoolOption, ExtensionOption, OrderedExtensionsOption

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
    
        Returns True if the correct user and password are specfied.  Returns
        False if the incorrect password was specified.  Returns None if the
        user doesn't exist in this password store.

        Note: Returing `False` is an active rejection of the login attempt.
        Return None to let the auth fall through to the next store in the
        chain.
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

    The "account-manager.password_store" may be an ordered list of password
    stores.  if it is a list, then each password store is queried in turn.
    """

    implements(IAccountChangeListener)

    _password_store = OrderedExtensionsOption('account-manager', 'password_store',
                                              IPasswordStore, include_missing=False)
    _password_format = Option('account-manager', 'password_format')
    stores = ExtensionPoint(IPasswordStore)
    change_listeners = ExtensionPoint(IAccountChangeListener)
    force_passwd_change = BoolOption('account-manager', 'force_passwd_change',
                                     True, doc="Forge the user to change "
                                     "password when it's reset.")
    persistent_sessions = BoolOption('account-manager', 'persistent_sessions',
                                     False, doc="Allow the user to be "
                                     "remembered across sessions without "
                                     "needing to re-authenticate. This is, "
                                     "user checks a \"Remember Me\" checkbox "
                                     "and, next time he visits the site, he'll "
                                     "be remembered")

    # Public API

    def get_users(self):
        users = []
        for store in self._password_store:
            users.extend(store.get_users())
        return users

    def has_user(self, user):
        exists = False
        for store in self._password_store:
            if store.has_user(user):
                exists = True
                break
            continue
        return exists

    def set_password(self, user, password):
        store = self.find_user_store(user)
        if store and not hasattr(store, 'set_password'):
            raise TracError('The authentication backend for the user, %s, '
                            'does not support setting the password' % user)
        elif not store:
            store = self.get_supporting_store('set_password')
        if store:
            if store.set_password(user, password):
                self._notify('created', user, password)
            else:
                self._notify('password_changed', user, password)
        else:
            raise TracError('None of the IPasswordStore components listed in '
                            'the trac.ini support setting the password or '
                            'creating users')

    def check_password(self, user, password):
        valid = False
        for store in self._password_store:
            valid = store.check_password(user, password)
            if valid  or (valid == False):
                break
            continue
        return valid

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
        self.log.debug('deleted user: %s' % user)
        store = self.find_user_store(user)
        if hasattr(store, 'delete_user'):
            if store and store.delete_user(user):
                self._notify('deleted', user)

    def supports(self, operation):
        try:
            stores = self.password_store
        except AttributeError:
            return False
        else:
            if self.get_supporting_store(operation):
                return True
            else:
                return False

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
                    return [store]
            # if the "password_format" is not set re-raise the AttributeError
            raise
    password_store = property(password_store)

    def get_supporting_store(self, operation):
        """Returns the IPasswordStore that implements the specified operaion

        None is returned if no supporting store can be found
        """
        supports = False
        for store in self.password_store:
            if hasattr(store, operation):
                supports = True
                break
            continue
        store = supports and store or None
        return store

    def get_all_supporting_stores(self, operation):
        """Returns a list of stores that implement the specified operation"""
        stores = []
        for store in self.password_store:
            if hasattr(store, operation):
                stores.append(store)
            continue
        return stores

    def find_user_store(self, user):
        """Locates which store contains the user specified.

        If the user isn't found in any IPasswordStore in the chain, None is
        returned
        """
        ignore_auth_case = self.env.config.get('trac', 'ignore_auth_case')
        user_stores = []
        for store in self._password_store:
            userlist = store.get_users()
            if ignore_auth_case:
                userlist = [u.lower() for u in userlist]
            user_stores.append((store, userlist))
            continue
        user = ignore_auth_case and user.lower() or user
        for store in user_stores:
            if user in store[1]:
                return store[0]
            continue
        return None

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

