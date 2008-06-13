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

import doctest
import unittest
try:
    import twill, subprocess
    INCLUDE_FUNCTIONAL_TESTS = True
except ImportError:    
    INCLUDE_FUNCTIONAL_TESTS = False

def suite():
    from acct_mgr.tests import htfile, db
    suite = unittest.TestSuite()
    suite.addTest(htfile.suite())
    suite.addTest(db.suite())
    if INCLUDE_FUNCTIONAL_TESTS:
        from acct_mgr.tests.functional import suite as functional_suite
        suite.addTest(functional_suite())
    return suite

if __name__ == '__main__':
    import sys
    if '--skip-functional-tests' in sys.argv:
        sys.argv.remove('--skip-functional-tests')
        INCLUDE_FUNCTIONAL_TESTS = False
    unittest.main(defaultTest='suite')
