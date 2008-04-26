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

import random
import string

from trac import perm, util
from trac.core import *
from trac.config import IntOption
from trac.notification import NotificationSystem, NotifyEmail
from trac.prefs import IPreferencePanelProvider
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
    cursor.execute("SELECT count(*) FROM session "
                   "WHERE sid=%s AND authenticated=1",
                   (user,))
    exists, = cursor.fetchone()
    if not exists:
        cursor.execute("INSERT INTO session "
                       "(sid, authenticated, last_visit) "
                       "VALUES (%s, 1, 0)",
                       (user,))

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
    template_name = 'reset_password_email.txt'
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
        self.data.update({
            'account': {
                'username': username,
                'password': password,
            },
            'login': {
                'link': self.env.abs_href.login(),
            }
        })

        projname = self.config.get('project', 'name')
        subject = '[%s] Trac password reset for user: %s' % (projname, username)

        NotifyEmail.notify(self, username, subject)


class AccountModule(Component):
    """Allows users to change their password, reset their password if they've
    forgotten it, or delete their account.  The settings for the AccountManager
    module must be set in trac.ini in order to use this.
    """

    implements(IPreferencePanelProvider, IRequestHandler, ITemplateProvider, INavigationContributor)

    _password_chars = string.ascii_letters + string.digits
    password_length = IntOption('account-manager', 'generated_password_length', 8,
                                'Length of the randomly-generated passwords '
                                'created when resetting the password for an '
                                'account.')

    def __init__(self):
        self._write_check(log=True)

    def _write_check(self, log=False):
        writable = AccountManager(self.env).supports('set_password')
        if not writable and log:
            self.log.warn('AccountModule is disabled because the password '
                          'store does not support writing.')
        return writable

    #IPreferencePanelProvider methods
    def get_preference_panels(self, req):
        if not self._write_check():
            return
        if req.authname and req.authname != 'anonymous':
            yield 'account', 'Account'

    def render_preference_panel(self, req, panel):
        data = {'account': self._do_account(req)}
        return 'prefs_account.html', data

    # IRequestHandler methods
    def match_request(self, req):
        return (req.path_info == '/reset_password'
                and self._write_check(log=True))

    def process_request(self, req):
        data = {'reset': self._do_reset_password(req)}
        return 'reset_password.html', data, None

    # INavigationContributor methods
    def get_active_navigation_item(self, req):
        return 'reset_password'

    def get_navigation_items(self, req):
        if not self.reset_password_enabled or LoginModule(self.env).enabled:
            return
        if req.authname == 'anonymous':
            yield 'metanav', 'reset_password', Markup('<a href="%s">Forgot your password?</a>') % req.href.reset_password()

    def reset_password_enabled(self):
        return (self.env.is_component_enabled(AccountModule)
                and NotificationSystem(self.env).smtp_enabled
                and self._write_check())
    reset_password_enabled = property(reset_password_enabled)

    def _do_account(self, req):
        if not req.authname or req.authname == 'anonymous':
            req.redirect(req.href.wiki())
        action = req.args.get('action')
        delete_enabled = AccountManager(self.env).supports('delete_user')
        data = {'delete_enabled': delete_enabled}
        if req.method == 'POST':
            if action == 'save':
                data.update(self._do_change_password(req))
            elif action == 'delete' and delete_enabled:
                data.update(self._do_delete(req))
            else:
                data.update({'error': 'Invalid action'})
        return data

    def _do_reset_password(self, req):
        if req.authname and req.authname != 'anonymous':
            return {'logged_in': True}
        if req.method != 'POST':
            return {}
        username = req.args.get('username')
        email = req.args.get('email')
        if not username:
            return {'error': 'Username is required'}
        if not email:
            return {'error': 'Email is required'}

        notifier = PasswordResetNotification(self.env)

        if email != notifier.email_map.get(username):
            return {'error': 'The email and username do not '
                             'match a known account.'}

        new_password = self._random_password()
        notifier.notify(username, new_password)
        AccountManager(self.env).set_password(username, new_password)
        return {'sent_to_email': email}

    def _random_password(self):
        return ''.join([random.choice(self._password_chars)
                        for _ in xrange(self.password_length)])

    def _do_change_password(self, req):
        user = req.authname
        mgr = AccountManager(self.env)

        old_password = req.args.get('old_password')
        if not old_password:
            return {'save_error': 'Old Password cannot be empty.'}
        if not mgr.check_password(user, old_password):
            return {'save_error': 'Old Password is incorrect.'}

        password = req.args.get('password')
        if not password:
            return {'save_error': 'Password cannot be empty.'}

        if password != req.args.get('password_confirm'):
            return {'save_error': 'The passwords must match.'}

        mgr.set_password(user, password)
        return {'message': 'Password successfully updated.'}

    def _do_delete(self, req):
        user = req.authname
        mgr = AccountManager(self.env)

        password = req.args.get('password')
        if not password:
            return {'delete_error': 'Password cannot be empty.'}
        if not mgr.check_password(user, password):
            return {'delete_error': 'Password is incorrect.'}

        mgr.delete_user(user)
        req.redirect(req.href.logout())

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

    def __init__(self):
        self._enable_check(log=True)

    def _enable_check(self, log=False):
        writable = AccountManager(self.env).supports('set_password')
        ignore_case = auth.LoginModule(self.env).ignore_case
        if log:
            if not writable:
                self.log.warn('RegistrationModule is disabled because the '
                              'password store does not support writing.')
            if ignore_case:
                self.log.warn('RegistrationModule is disabled because '
                              'ignore_auth_case is enabled in trac.ini.  '
                              'This setting needs disabled to support '
                              'registration.')
        return writable and not ignore_case

    #INavigationContributor methods

    def get_active_navigation_item(self, req):
        return 'register'

    def get_navigation_items(self, req):
        if not self._enable_check():
            return
        if req.authname == 'anonymous':
            yield 'metanav', 'register', Markup('<a href="%s">Register</a>') % req.href.register()

    # IRequestHandler methods

    def match_request(self, req):
        return req.path_info == '/register' and self._enable_check(log=True)

    def process_request(self, req):
        if req.authname != 'anonymous':
            req.redirect(req.href.prefs('account'))
        action = req.args.get('action')
        data = {}
        if req.method == 'POST' and action == 'create':
            try:
                _create_user(req, self.env)
            except TracError, e:
                data['registration_error'] = e.message
            else:
                req.redirect(req.href.login())
        data['reset_password_enabled'] = \
            (self.env.is_component_enabled(AccountModule)
             and NotificationSystem(self.env).smtp_enabled)

        return 'register.html', data, None


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
            data = {
                'referer': self._referer(req),
                'reset_password_enabled': AccountModule(self.env).reset_password_enabled
            }
            if req.method == 'POST':
                data['login_error'] = 'Invalid username or password'
            return 'login.html', data, None
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

