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

def suite():
    from acct_mgr.tests import htfile
    suite = unittest.TestSuite()
    suite.addTest(htfile.suite())
    return suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
