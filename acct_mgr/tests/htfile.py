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


class HtDigestTestCase(_BaseTestCase):
    def setUp(self):
        _BaseTestCase.setUp(self)
        self.env.config.set('account-manager', 'password_store',
                            'HtDigestStore')
        self.env.config.set('account-manager', 'htdigest_realm',
                            'TestRealm')

    def test_userline(self):
        store = HtDigestStore(self.env)
        self.assertEqual(store.userline('user', 'password'),
                         'user:TestRealm:752b304cc7cf011d69ee9b79e2cd0866')

class HtPasswdTestCase(_BaseTestCase):
    def setUp(self):
        _BaseTestCase.setUp(self)
        self.env.config.set('account-manager', 'password_store',
                            'HtPasswdStore')

    def test_md5(self):
        self._do_password_test('test_md5',
                               'user:$apr1$xW/09...$fb150dT95SoL1HwXtHS/I0\n')

    def test_crypt(self):
        self._do_password_test('test_crypt', 'user:QdQ/xnl2v877c\n')

    def test_sha(self):
        self._do_password_test('test_sha',
                               'user:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=\n')

    def _do_password_test(self, filename, content):
        store = HtPasswdStore(self.env)
        filename = self._create_file(filename, content=content)
        self.env.config.set('account-manager', 'password_file', filename)
        self.assertTrue(store.check_password('user', 'password'))


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(HtDigestTestCase, 'test'))
    suite.addTest(unittest.makeSuite(HtPasswdTestCase, 'test'))
    return suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')

