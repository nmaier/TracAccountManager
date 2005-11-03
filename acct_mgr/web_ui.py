# -*- coding: iso8859-1 -*-
#
# Copyright (C) 2005 Matthew Good <trac@matt-good.net>
#
# "THE BEER-WARE LICENSE" (Revision 42):
# <trac@matt-good.net> wrote this file.  As long as you retain this notice you
# can do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return.   Matthew Good
#
# Author: Matthew Good <trac@matt-good.net>

from __future__ import generators

from trac import perm, util
from trac.core import *
from trac.web import auth
from trac.web.api import IAuthenticator
from trac.web.main import IRequestHandler
from trac.web.chrome import INavigationContributor, ITemplateProvider

from api import AccountManager

class AccountModule(Component):
    """Allows users to change their password or delete their account.
    The settings for the AccountManager module must be set in trac.ini
    in order to use this.
    """

    implements(INavigationContributor, IRequestHandler, ITemplateProvider)

    #INavigationContributor methods
    def get_active_navigation_item(self, req):
        return 'account'

    def get_navigation_items(self, req):
        if req.authname != 'anonymous':
            yield 'metanav', 'account', '<a href="%s">My Account</a>' \
                  % (self.env.href.account())

    # IRequestHandler methods
    def match_request(self, req):
        return req.path_info == '/account'

    def process_request(self, req):
        if req.authname == 'anonymous':
            req.redirect(self.env.href.wiki())
        action = req.args.get('action')
        if req.method == 'POST':
            if action == 'change_password':
                self._do_change_password(req)
            elif action == 'delete':
                self._do_delete(req)
        return 'account.cs', None

    def _do_change_password(self, req):
        user = req.authname
        password = req.args.get('password')
        if not password:
            req.hdf['account.error'] = 'Password cannot be empty.'
            return

        if password != req.args.get('password_confirm'):
            req.hdf['account.error'] = 'The passwords must match.'
            return

        AccountManager(self.env).set_password(user, password)
        req.hdf['account.message'] = 'Password successfully updated.'

    def _do_delete(self, req):
        user = req.authname
        AccountManager(self.env).delete_user(user)
        req.redirect(self.env.href.logout())

    # ITemplateProvider
    
    def get_htdocs_dirs(self):
        """Return the absolute path of a directory containing additional
        static resources (such as images, style sheets, etc).
        """
        return []

    def get_templates_dirs(self):
        """Return the absolute path of the directory containing the provided
        ClearSilver templates.
        """
        from pkg_resources import resource_filename
        return [resource_filename(__name__, 'templates')]

class RegistrationModule(Component):
    """Provides users the ability to register a new account.
    Requires configuration of the AccountManager module in trac.ini.
    """

    implements(INavigationContributor, IRequestHandler, ITemplateProvider)

    #INavigationContributor methods

    def get_active_navigation_item(self, req):
        return 'register'

    def get_navigation_items(self, req):
        if req.authname == 'anonymous':
            yield 'metanav', 'register', '<a href="%s">Register</a>' \
                  % (self.env.href.register())

    # IRequestHandler methods

    def match_request(self, req):
        return req.path_info == '/register'

    def process_request(self, req):
        if req.authname != 'anonymous':
            req.redirect(self.env.href.account())
        action = req.args.get('action')
        if req.method == 'POST' and action == 'create':
            self._do_create(req)
        return 'register.cs', None

    def _do_create(self, req):
        mgr = AccountManager(self.env)

        user = req.args.get('user')
        if mgr.has_user(user):
            req.hdf['registration.error'] = \
                'Another account with that name already exists.'
            return

        password = req.args.get('password')
        if not password:
            req.hdf['registration.error'] = 'Password cannot be empty.'
            return

        if password != req.args.get('password_confirm'):
            req.hdf['registration.error'] = 'The passwords must match.'
            return

        mgr.set_password(user, password)
        req.redirect(self.env.href.login())

    # ITemplateProvider
    
    def get_htdocs_dirs(self):
        """Return the absolute path of a directory containing additional
        static resources (such as images, style sheets, etc).
        """
        return []

    def get_templates_dirs(self):
        """Return the absolute path of the directory containing the provided
        ClearSilver templates.
        """
        from pkg_resources import resource_filename
        return [resource_filename(__name__, 'templates')]

def if_enabled(func):
    def wrap(self, *args, **kwds):
        if not self.enabled:
            return None
        return func(self, *args, **kwds)
    return wrap

class LoginModule(auth.LoginModule):

    def authenticate(self, req):
        if req.method == 'POST' and req.path_info.startswith('/login'):
            req.remote_user = self._remote_user(req)
        return auth.LoginModule.authenticate(self, req)
    authenticate = if_enabled(authenticate)

    match_request = if_enabled(auth.LoginModule.match_request)

    def process_request(self, req):
        if req.path_info.startswith('/login') and req.authname == 'anonymous':
            req.hdf['referer'] = self._referer(req)
            if req.method == 'POST':
                req.hdf['login.error'] = 'Invalid username or password'
            return 'login.cs', None
        return auth.LoginModule.process_request(self, req)

    def _do_login(self, req):
        if not req.remote_user:
            req.redirect(self.env.abs_href())
        return auth.LoginModule._do_login(self, req)

    def _remote_user(self, req):
        user = req.args.get('user')
        if AccountManager(self.env).check_password(user,
                req.args.get('password')):
            return user
        return None

    def _redirect_back(self, req):
        """Redirect the user back to the URL she came from."""
        referer = self._referer(req)
        if referer and not referer.startswith(req.base_url):
            # don't redirect to external sites
            referer = None
        req.redirect(referer or self.env.abs_href())

    def _referer(self, req):
        return req.args.get('referer') or req.get_header('Referer')

    def enabled(self):
        # Users should disable the built-in authentication to use this one
        return not self.env.is_component_enabled(auth.LoginModule)
    enabled = property(enabled)

