# -*- coding: utf-8 -*-
#
# Copyright (C) 2007 Matthew Good <trac@matt-good.net>
#
# "THE BEER-WARE LICENSE" (Revision 42):
# <trac@matt-good.net> wrote this file.  As long as you retain this notice you
# can do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return.   Matthew Good
#
# Author: Matthew Good <trac@matt-good.net>

import os.path
import shutil
import tempfile
import unittest

from trac.test import EnvironmentStub, Mock

from acct_mgr.db import SessionStore

class _BaseTestCase(unittest.TestCase):
    def setUp(self):
        #self.basedir = os.path.realpath(tempfile.mkdtemp())
        self.env = EnvironmentStub()
        self.env.config.set('account-manager', 'password_store',
                            'SessionStore')
        self.store = SessionStore(self.env)
        #self.env.path = os.path.join(self.basedir, 'trac-tempenv')
        #os.mkdir(self.env.path)

    def test_get_users(self):
        db = self.env.get_db_cnx()
        cursor = db.cursor()
        cursor.executemany("INSERT INTO session_attribute "
                       "(sid,authenticated,name,value) "
                       "VALUES (%s,1,'password',%s)",
                       [('a', 'a'),
                        ('b', 'b'),
                        ('c', 'c')])
        self.assertEqual(['a', 'b', 'c'], list(self.store.get_users()))

    def test_has_user(self):
        db = self.env.get_db_cnx()
        cursor = db.cursor()
        cursor.execute("INSERT INTO session_attribute "
                       "(sid,authenticated,name,value) "
                       "VALUES (%s,1,'password',%s)",
                       ('bar', 'bar'))

        self.assertFalse(self.store.has_user('foo'))
        self.assertTrue(self.store.has_user('bar'))

    def test_create_user(self):
        self.assertFalse(self.store.has_user('foo'))
        self.store.set_password('foo', 'password')
        self.assertTrue(self.store.has_user('foo'))
 
    def test_update_password(self):
        self.store.set_password('foo', 'pass1')
        self.assertFalse(self.store.check_password('foo', 'pass2'))
        self.store.set_password('foo', 'pass2')
        self.assertTrue(self.store.check_password('foo', 'pass2'))

    def test_delete_user(self):
        self.store.set_password('foo', 'password')
        self.assertTrue(self.store.has_user('foo'))
        self.assertTrue(self.store.delete_user('foo'))
        self.assertFalse(self.store.has_user('foo'))

    def test_delete_nonexistant_user(self):
        self.assertFalse(self.store.has_user('foo'))
        self.assertFalse(self.store.delete_user('foo'))


class HtDigestTestCase(_BaseTestCase):
    def setUp(self):
        _BaseTestCase.setUp(self)
        self.env.config.set('account-manager', 'hash_method',
                            'HtDigestHashMethod')
        self.env.config.set('account-manager', 'htdigest_realm',
                            'TestRealm')


class HtPasswdTestCase(_BaseTestCase):
    def setUp(self):
        _BaseTestCase.setUp(self)
        self.env.config.set('account-manager', 'hash_method',
                            'HtPasswdHashMethod')


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(HtDigestTestCase, 'test'))
    suite.addTest(unittest.makeSuite(HtPasswdTestCase, 'test'))
    return suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')


