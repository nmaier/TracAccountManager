# -*- coding: utf-8 -*-
#
# Copyright (C) 2008 Matthew Good <trac@matt-good.net>
#
# "THE BEER-WARE LICENSE" (Revision 42):
# <trac@matt-good.net> wrote this file.  As long as you retain this notice you
# can do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return.   Matthew Good
#
# Author: Pedro Algarvio <ufs@ufsoft.org>

import os
import unittest

from trac.test import TestSetup
from trac.tests.functional import twill, b, tc, internal_error, ConnectError
from trac.tests.functional import FunctionalTestCaseSetup as \
                                                    TracFunctionalTestCaseSetup
from trac.tests.functional import FunctionalTwillTestCaseSetup
from trac.tests.functional.tester import FunctionalTester

import acct_mgr

# Setup these vars here because they will be used on the following imports
acct_mgr_source_tree = os.path.normpath(
                                    os.path.join(acct_mgr.__file__, '..', '..'))
# testing.log gets any unused output from subprocesses
logfile = open(os.path.join(acct_mgr_source_tree, 'testing.log'), 'w')
# functional-testing.log gets the twill output
twill.set_output(open(os.path.join(acct_mgr_source_tree,
                                   'functional-testing.log'), 'w'))

from acct_mgr.tests.functional.testenv import AcctMgrFuntionalTestEnvironment
from acct_mgr.tests.functional.tester import AcctMgrFunctionalTester


class FunctionalTestSuite(TestSetup):
    def setUp(self, port=None):
        if port == None:
            port = 8000 + os.getpid() % 1000
            dirname = "testenv"
        else:
            dirname = "testenv%s" % port
        dirname = os.path.join(acct_mgr_source_tree, dirname)
        
        baseurl = "http://localhost:%s" % port
        self._testenv = AcctMgrFuntionalTestEnvironment(dirname, port, baseurl)
        self._testenv.start()
        self._tester = AcctMgrFunctionalTester(baseurl, self._testenv.repo_url())
        self.fixture = (self._testenv, self._tester)
    
    def tearDown(self):
        self._testenv.stop()
        

class FunctionalTestCaseSetup(TracFunctionalTestCaseSetup):
    def setUp(self):
        self._testenv, self._tester = self.fixture
        self._smtpd = self._testenv.smtpd 
        
def suite():    
    from acct_mgr.tests.functional.testcases import suite
    suite = suite()
    return suite
    
if __name__ == '__main__':
    unittest.main(defaultTest='suite')
    
    
