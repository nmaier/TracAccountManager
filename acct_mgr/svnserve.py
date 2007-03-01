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

from trac.core import *
from trac.config import Configuration
from trac.versioncontrol import RepositoryManager

from api import IPasswordStore
from util import EnvRelativePathOption

class SvnServePasswordStore(Component):
    """PasswordStore implementation for reading svnserve's password file format
    """

    implements(IPasswordStore)

    filename = EnvRelativePathOption('account-manager', 'password_file',
                                     doc='Path to the users file.  Leave '
                                         'blank to locate the users file '
                                         'by reading svnserve.conf')

    def __init__(self):
        repo_dir = RepositoryManager(self.env).repository_dir
        self._svnserve_conf = Configuration(os.path.join(repo_dir, 'svnserve.conf'))
        self._userconf = None

    def _config(self):
        filename = self.filename
        if not filename:
            self._svnserve_conf.parse_if_needed()
            filename = self._svnserve_conf['general'].getpath('password-db')
        if self._userconf is None or filename != self._userconf.filename:
            self._userconf = Configuration(filename)
        else:
            self._userconf.parse_if_needed()
        return self._userconf
    _config = property(_config)

    # IPasswordStore methods

    def get_users(self):
        return [user for (user,password) in self._config.options('users')]

    def has_user(self, user):
        return user in self._config['users']
 
    def set_password(self, user, password):
        cfg = self._config
        cfg.set('users', user, password)
        cfg.save()
 
    def check_password(self, user, password):
        return password == self._config.get('users', user)

    def delete_user(self, user):
        cfg = self._config
        cfg.remove('users', user)
        cfg.save()
