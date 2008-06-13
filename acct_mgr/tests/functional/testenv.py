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
import sys
import time

from subprocess import call, Popen

from trac.admin import console
from trac.web import standalone
from trac.env import open_environment
from trac.tests.functional.compat import rmtree, close_fds

from trac.tests.functional.testenv import FunctionalTestEnvironment
from trac.tests.notification import SMTPThreadedServer

from acct_mgr.pwhash import htpasswd
from acct_mgr.tests.functional import logfile
from acct_mgr.tests.functional import tc, ConnectError
from acct_mgr.tests.functional.smtpd import AcctMgrSMTPThreadedServer

class AcctMgrFuntionalTestEnvironment(FunctionalTestEnvironment):
    
    def __init__(self, dirname, port, url):
        FunctionalTestEnvironment.__init__(self, dirname, port, url)
        self.smtp_port = self.port + os.getpid() % 1000
        self.smtpd = AcctMgrSMTPThreadedServer(self.smtp_port)
        
        config = self.get_trac_environment().config
        # Enabled Account Manager
        config.set('components', 'acct_mgr.*', 'enabled')
        # Disable trac's LoginModule
        config.set('components', 'trac.web.auth.LoginModule', 'disabled')
        # Setup Account Manager
        config.set('account-manager', 'password_file', self.htpasswd)
        config.set('account-manager', 'password_format', 'htpasswd')
        config.set('account-manager', 'password_store', 'HtPasswdStore')
        # Setup Notification
        config.set('notification', 'smtp_enabled', 'true')
        config.set('notification', 'smtp_from', 'testenv%s@localhost' % self.port)
        config.set('notification', 'smtp_port', self.smtp_port)
        config.set('notification', 'smtp_server', 'localhost')
        config.set('project', 'url', self.url)
        config.set('project', 'admin', 'testenv%s@localhost' % self.port)
        config.set('trac', 'base_url', self.url)
               
        config.save()
        
    def start(self):
        """Starts the webserver"""
        if 'FIGLEAF' in os.environ:
            exe = os.environ['FIGLEAF']
        else:
            exe = sys.executable
        server = Popen([exe, standalone.__file__,
                        "--port=%s" % self.port, "-s",
                        "--hostname=localhost",
                        self.tracdir],
                       stdout=logfile, stderr=logfile,
                       close_fds=close_fds,
                       cwd=self.command_cwd,
                      )
        self.pid = server.pid
        # Verify that the url is ok
        timeout = 30
        while timeout:
            try:
                tc.go(self.url)
                break
            except ConnectError:
                time.sleep(1)
            timeout -= 1
        else:
            raise Exception('Timed out waiting for server to start.')
        tc.url(self.url)
        self.smtpd.start()
        
    def stop(self):
        FunctionalTestEnvironment.stop(self)
        self.smtpd.stop()
        
    def create(self):
        """Create a new test environment; Trac, Subversion,
        authentication."""
        if os.mkdir(self.dirname):
            raise Exception('unable to create test environment')
        if call(["svnadmin", "create", self.repodir], stdout=logfile,
                stderr=logfile, close_fds=close_fds):
            raise Exception('unable to create subversion repository')
        self._tracadmin('initenv', 'testenv%s' % self.port,
                        'sqlite:db/trac.db', 'svn', self.repodir)
        
        if os.path.exists(self.htpasswd):
            os.unlink(self.htpasswd)
        self.adduser('admin')        
        self.adduser('user')
        self._tracadmin('permission', 'add', 'admin', 'TRAC_ADMIN')
        # Setup Trac logging
        env = self.get_trac_environment()
        env.config.set('logging', 'log_type', 'file')
        env.config.save()

    def adduser(self, user):
        """Add a user to the environment.  Password is the username."""
        f = open(self.htpasswd, 'a')
        f.write("%s:%s\n" % (user, htpasswd(user)))
        f.close()
        
    def _tracadmin(self, *args):
        """Internal utility method for calling trac-admin"""
        retval = call([sys.executable, console.__file__, self.tracdir]
                      + list(args), stdout=logfile, stderr=logfile,
                      close_fds=close_fds, cwd=self.command_cwd)
        if retval:
            raise Exception('Failed with exitcode %s running trac-admin ' \
                            'with %r' % (retval, args))
