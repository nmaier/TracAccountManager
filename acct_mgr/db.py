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

from trac.core import *
from trac.config import ExtensionOption

from api import IPasswordStore
from pwhash import IPasswordHashMethod

class SessionStore(Component):
    implements(IPasswordStore)

    hash_method = ExtensionOption('account-manager', 'hash_method',
                                  IPasswordHashMethod, 'HtDigestHashMethod')

    def get_users(self):
        """Returns an iterable of the known usernames
        """
        db = self.env.get_db_cnx()
        cursor = db.cursor()
        cursor.execute("SELECT DISTINCT sid FROM session_attribute "
                       "WHERE authenticated=1 AND name='password'")
        for sid, in cursor:
            yield sid
 
    def has_user(self, user):
        db = self.env.get_db_cnx()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM session_attribute "
                       "WHERE authenticated=1 AND name='password' "
                       "AND sid=%s", (user,))
        for row in cursor:
            return True
        return False

    def set_password(self, user, password):
        """Sets the password for the user.  This should create the user account
        if it doesn't already exist.
        Returns True if a new account was created, False if an existing account
        was updated.
        """
        hash = self.hash_method.generate_hash(user, password)
        db = self.env.get_db_cnx()
        cursor = db.cursor()
        cursor.execute("UPDATE session_attribute "
                       "SET value=%s "
                       "WHERE authenticated=1 AND name='password' "
                       "AND sid=%s", (hash, user))
        if cursor.rowcount > 0:
            db.commit()
            return False # updated existing password
        cursor.execute("INSERT INTO session_attribute "
                       "(sid,authenticated,name,value) "
                       "VALUES (%s,1,'password',%s)",
                       (user, hash))
        db.commit()
        return True

    def check_password(self, user, password):
        """Checks if the password is valid for the user.
        """
        db = self.env.get_db_cnx()
        cursor = db.cursor()
        cursor.execute("SELECT value FROM session_attribute "
                       "WHERE authenticated=1 AND name='password' "
                       "AND sid=%s", (user,))
        for hash, in cursor:
            return self.hash_method.check_hash(user, password, hash)
        return False

    def delete_user(self, user):
        """Deletes the user account.
        Returns True if the account existed and was deleted, False otherwise.
        """
        if not self.has_user(user):
            return False
        db = self.env.get_db_cnx()
        cursor = db.cursor()
        cursor.execute("DELETE FROM session_attribute "
                       "WHERE authenticated=1 AND name='password' "
                       "AND sid=%s", (user,))
        # TODO cursor.rowcount doesn't seem to get # deleted
        # is there another way to get count instead of using has_user?
        db.commit()
        return True
