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

from __future__ import generators

import random
import string

from trac import perm, util
from trac.core import *
from trac.config import IntOption
from trac.notification import NotificationSystem, NotifyEmail
from trac.web import auth
from trac.web.api import IAuthenticator
from trac.web.main import IRequestHandler
from trac.web.chrome import INavigationContributor, ITemplateProvider
from trac.util import Markup

from api import AccountManager

def _create_user(req, env, check_permissions=True):
    mgr = AccountManager(env)

    user = req.args.get('user')
    if not user:
        raise TracError('Username cannot be empty.')

    if mgr.has_user(user):
        raise TracError('Another account with that name already exists.')

    if check_permissions:
        # disallow registration of accounts which have existing permissions
        permission_system = perm.PermissionSystem(env)
        if permission_system.get_user_permissions(user) != \
           permission_system.get_user_permissions('authenticated'):
            raise TracError('Another account with that name already exists.')

    password = req.args.get('password')
    if not password:
        raise TracError('Password cannot be empty.')

    if password != req.args.get('password_confirm'):
        raise TracError('The passwords must match.')

    mgr.set_password(user, password)

    db = env.get_db_cnx()
    cursor = db.cursor()
    for key in ('name', 'email'):
        value = req.args.get(key)
        if not value:
            continue
        cursor.execute("UPDATE session_attribute SET value=%s "
                       "WHERE name=%s AND sid=%s AND authenticated=1",
                       (value, key, user))
        if not cursor.rowcount:
            cursor.execute("INSERT INTO session_attribute "
                           "(sid,authenticated,name,value) "
                           "VALUES (%s,1,%s,%s)",
                           (user, key, value))
    db.commit()


class PasswordResetNotification(NotifyEmail):
    template_name = 'reset_password_email.cs'
    _username = None

    def get_recipients(self, resid):
        return ([resid],[])

    def get_smtp_address(self, addr):
        """Overrides `get_smtp_address` in order to prevent CCing users
        other than the user whose password is being reset.
        """
        if addr == self._username:
            return NotifyEmail.get_smtp_address(self, addr)
        else:
            return None

    def notify(self, username, password):
        # save the username for use in `get_smtp_address`
        self._username = username
        self.hdf['account.username'] = username
        self.hdf['account.password'] = password
        self.hdf['login.link'] = self.env.abs_href.login()

        projname = self.config.get('project', 'name')
        subject = '[%s] Trac password reset for user: %s' % (projname, username)

        NotifyEmail.notify(self, username, subject)


class AccountModule(Component):
    """Allows users to change their password, reset their password if they've
    forgotten it, or delete their account.  The settings for the AccountManager
    module must be set in trac.ini in order to use this.
    """

    implements(INavigationContributor, IRequestHandler, ITemplateProvider)

    _password_chars = string.ascii_letters + string.digits
    password_length = IntOption('account-manager', 'generated_password_length', 8,
                                'Length of the randomly-generated passwords '
                                'created when resetting the password for an '
                                'account.')

    #INavigationContributor methods
    def get_active_navigation_item(self, req):
        return 'account'

    def get_navigation_items(self, req):
        if req.authname != 'anonymous':
            yield 'metanav', 'account', Markup('<a href="%s">My Account</a>',
                                               (req.href.account()))

    # IRequestHandler methods
    def match_request(self, req):
        return req.path_info in ('/account', '/reset_password')

    def process_request(self, req):
        if req.path_info == '/account':
            self._do_account(req)
            return 'account.cs', None
        elif req.path_info == '/reset_password':
            self._do_reset_password(req)
            return 'reset_password.cs', None

    def _do_account(self, req):
        if req.authname == 'anonymous':
            req.redirect(self.env.href.wiki())
        action = req.args.get('action')
        if req.method == 'POST':
            if action == 'change_password':
                self._do_change_password(req)
            elif action == 'delete':
                self._do_delete(req)

    def _do_reset_password(self, req):
        if req.authname != 'anonymous':
            req.hdf['reset.logged_in'] = True
            req.hdf['account_href'] = req.href.account()
            return
        if req.method == 'POST':
            username = req.args.get('username')
            email = req.args.get('email')
            if not username:
                req.hdf['reset.error'] = 'Username is required'
                return
            if not email:
                req.hdf['reset.error'] = 'Email is required'
                return

            notifier = PasswordResetNotification(self.env)

            if email != notifier.email_map.get(username):
                req.hdf['reset.error'] = 'The email and username do not ' \
                                         'match a known account.'
                return

            new_password = self._random_password()
            notifier.notify(username, new_password)
            AccountManager(self.env).set_password(username, new_password)
            req.hdf['reset.sent_to_email'] = email

    def _random_password(self):
        return ''.join([random.choice(self._password_chars)
                        for _ in xrange(self.password_length)])

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
            yield 'metanav', 'register', Markup('<a href="%s">Register</a>',
                                                (self.env.href.register()))

    # IRequestHandler methods

    def match_request(self, req):
        return req.path_info == '/register'

    def process_request(self, req):
        if req.authname != 'anonymous':
            req.redirect(self.env.href.account())
        action = req.args.get('action')
        if req.method == 'POST' and action == 'create':
            try:
                _create_user(req, self.env)
            except TracError, e:
                req.hdf['registration.error'] = e.message
            else:
                req.redirect(self.env.href.login())
        req.hdf['reset_password_enabled'] = \
            (self.env.is_component_enabled(AccountModule)
             and NotificationSystem(self.env).smtp_enabled)

        return 'register.cs', None


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

    implements(ITemplateProvider)

    def authenticate(self, req):
        if req.method == 'POST' and req.path_info.startswith('/login'):
            req.environ['REMOTE_USER'] = self._remote_user(req)
        return auth.LoginModule.authenticate(self, req)
    authenticate = if_enabled(authenticate)

    match_request = if_enabled(auth.LoginModule.match_request)

    def process_request(self, req):
        if req.path_info.startswith('/login') and req.authname == 'anonymous':
            req.hdf['referer'] = self._referer(req)
            if self.env.is_component_enabled(AccountModule) \
               and NotificationSystem(self.env).smtp_enabled:
                req.hdf['trac.href.reset_password'] = req.href.reset_password()
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
        password = req.args.get('password')
        if not user or not password:
            return None
        if AccountManager(self.env).check_password(user, password):
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

