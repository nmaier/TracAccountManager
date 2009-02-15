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

import os.path
import shutil
import tempfile
import unittest

from trac.test import EnvironmentStub, Mock

from acct_mgr.htfile import HtDigestStore, HtPasswdStore

class _BaseTestCase(unittest.TestCase):
    def setUp(self):
        self.basedir = os.path.realpath(tempfile.mkdtemp())
        self.env = EnvironmentStub()
        self.env.path = os.path.join(self.basedir, 'trac-tempenv')
        os.mkdir(self.env.path)

    def tearDown(self):
        shutil.rmtree(self.basedir)

    def _create_file(self, *path, **kw):
        filename = os.path.join(self.basedir, *path)
        dirname = os.path.dirname(filename)
        if not os.path.exists(dirname):
            os.makedirs(dirname)
        fd = file(filename, 'w')
        content = kw.get('content')
        if content is not None:
            fd.write(content)
        fd.close()
        return filename

    def _init_password_file(self, filename, content):
        filename = self._create_file(filename, content=content)
        self.env.config.set('account-manager', 'password_file', filename)

    def _do_password_test(self, filename, content):
        self._init_password_file(filename, content)
        self.assertTrue(self.store.check_password('user', 'password'))


class HtDigestTestCase(_BaseTestCase):
    def setUp(self):
        _BaseTestCase.setUp(self)
        self.env.config.set('account-manager', 'password_store',
                            'HtDigestStore')
        self.env.config.set('account-manager', 'htdigest_realm',
                            'TestRealm')
        self.store = HtDigestStore(self.env)

    def test_userline(self):
        self.assertEqual(self.store.userline('user', 'password'),
                         'user:TestRealm:752b304cc7cf011d69ee9b79e2cd0866')

    def test_file(self):
        self._do_password_test('test_file', 
                               'user:TestRealm:752b304cc7cf011d69ee9b79e2cd0866')

    def test_unicode(self):
        self.env.config.set('account-manager', 'htdigest_realm',
                            u'UnicodeRealm\u4e60')
        user = u'\u4e61'
        password = u'\u4e62'
        self._init_password_file('test_unicode', '')
        self.store.set_password(user, password)
        self.assertEqual([user], list(self.store.get_users()))
        self.assertTrue(self.store.check_password(user, password))
        self.assertTrue(self.store.delete_user(user))
        self.assertEqual([], list(self.store.get_users()))


class HtPasswdTestCase(_BaseTestCase):
    def setUp(self):
        _BaseTestCase.setUp(self)
        self.env.config.set('account-manager', 'password_store',
                            'HtPasswdStore')
        self.store = HtPasswdStore(self.env)

    def test_md5(self):
        self._do_password_test('test_md5',
                               'user:$apr1$xW/09...$fb150dT95SoL1HwXtHS/I0\n')

    def test_crypt(self):
        self._do_password_test('test_crypt', 'user:QdQ/xnl2v877c\n')

    def test_sha(self):
        self._do_password_test('test_sha',
                               'user:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=\n')

    def test_no_trailing_newline(self):
        self._do_password_test('test_no_trailing_newline',
                               'user:$apr1$xW/09...$fb150dT95SoL1HwXtHS/I0')

    def test_add_with_no_trailing_newline(self):
        filename = self._create_file('test_add_with_no_trailing_newline',
                                     content='user:$apr1$'
                                             'xW/09...$fb150dT95SoL1HwXtHS/I0')
        self.env.config.set('account-manager', 'password_file', filename)
        self.assertTrue(self.store.check_password('user', 'password'))
        self.store.set_password('user2', 'password2')
        self.assertTrue(self.store.check_password('user', 'password'))
        self.assertTrue(self.store.check_password('user2', 'password2'))

    def test_unicode(self):
        user = u'\u4e61'
        password = u'\u4e62'
        self._init_password_file('test_unicode', '')
        self.store.set_password(user, password)
        self.assertEqual([user], list(self.store.get_users()))
        self.assertTrue(self.store.check_password(user, password))
        self.assertTrue(self.store.delete_user(user))
        self.assertEqual([], list(self.store.get_users()))


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(HtDigestTestCase, 'test'))
    suite.addTest(unittest.makeSuite(HtPasswdTestCase, 'test'))
    return suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')

