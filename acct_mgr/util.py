# -*- coding: utf8 -*-
#
# Copyright (C) 2005 Matthew Good <trac@matt-good.net>
#
# "THE BEER-WARE LICENSE" (Revision 42):
# <trac@matt-good.net> wrote this file.  As long as you retain this notice you
# can do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return.   Matthew Good
#
# Author: Matthew Good <trac@matt-good.net>

import os

from trac.config import Option

class EnvRelativePathOption(Option):
 
    def __get__(self, instance, owner):
        if instance is None:
            return self
        path = super(EnvRelativePathOption, self).__get__(instance, owner)
        if not path:
            return path
        return os.path.normpath(os.path.join(instance.env.path, path))


# os.urandom was added in Python 2.4
# try to fall back on pseudo-random values if it's not available
try:
    from os import urandom
except ImportError:
    from random import randrange
    def urandom(n):
        return ''.join([chr(randrange(256)) for _ in xrange(n)])


