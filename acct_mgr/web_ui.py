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

import base64
import os
import random
import string

from trac import perm, util
from trac.core import *
from trac.config import IntOption
from trac.notification import NotificationSystem, NotifyEmail
from trac.prefs import IPreferencePanelProvider
from trac.web import auth
from trac.web.api import IAuthenticator
from trac.web.main import IRequestHandler, IRequestFilter
from trac.web import chrome
from trac.web.chrome import INavigationContributor, ITemplateProvider
from genshi.builder import tag

from api import AccountManager
from acct_mgr.util import urandom

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


class SingleUserNofification(NotifyEmail):
    """Helper class used for account email notifications which should only be
    sent to one persion, not including the rest of the normally CCed users
    """
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

    def notify(self, username, subject):
        # save the username for use in `get_smtp_address`
        self._username = username
        old_public_cc = self.config.getbool('notification', 'use_public_cc')
        # override public cc option so that the user's email is included in the To: field
        self.config.set('notification', 'use_public_cc', 'true')
        try:
            NotifyEmail.notify(self, username, subject)
        finally:
            self.config.set('notification', 'use_public_cc', old_public_cc)


class PasswordResetNotification(SingleUserNofification):
    template_name = 'reset_password_email.txt'

    def notify(self, username, password):
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

        SingleUserNofification.notify(self, username, subject)


class AccountModule(Component):
    """Allows users to change their password, reset their password if they've
    forgotten it, or delete their account.  The settings for the AccountManager
    module must be set in trac.ini in order to use this.
    """

    implements(IPreferencePanelProvider, IRequestHandler, ITemplateProvider,
               INavigationContributor, IRequestFilter)

    _password_chars = string.ascii_letters + string.digits
    password_length = IntOption('account-manager', 'generated_password_length',
                                8, 'Length of the randomly-generated passwords '
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

    # IRequestFilter methods
    def pre_process_request(self, req, handler):
        return handler

    def post_process_request(self, req, template, data, content_type):
        if req.authname and req.authname != 'anonymous':
            if req.session.get('force_change_passwd', False):
                redirect_url = req.href.prefs('account')
                if req.path_info != redirect_url:
                    req.redirect(redirect_url)
        return (template, data, content_type)

    # INavigationContributor methods
    def get_active_navigation_item(self, req):
        return 'reset_password'

    def get_navigation_items(self, req):
        if not self.reset_password_enabled or LoginModule(self.env).enabled:
            return
        if req.authname == 'anonymous':
            yield 'metanav', 'reset_password', tag.a(
                "Forgot your password?", href=req.href.reset_password())

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
        force_change_password = req.session.get('force_change_passwd', False)
        if req.method == 'POST':
            if action == 'save':
                data.update(self._do_change_password(req))
                if force_change_password:
                    del(req.session['force_change_passwd'])
                    req.session.save()
                    chrome.add_notice(req, MessageWrapper(tag(
                        "Thank you for taking the time to update your password."
                    )))
                    force_change_password = False
            elif action == 'delete' and delete_enabled:
                data.update(self._do_delete(req))
            else:
                data.update({'error': 'Invalid action'})
        if force_change_password:
            chrome.add_warning(req, MessageWrapper(tag(
                "You are required to change password because of a recent "
                "password change request. ",
                tag.b("Please change your password now."))))
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
        mgr = AccountManager(self.env)
        mgr.set_password(username, new_password)
        if mgr.force_passwd_change:
            db = self.env.get_db_cnx()
            cursor = db.cursor()
            cursor.execute("UPDATE session_attribute SET value=%s "
                           "WHERE name=%s AND sid=%s AND authenticated=1",
                           (1, "force_change_passwd", username))
            if not cursor.rowcount:
                cursor.execute("INSERT INTO session_attribute "
                               "(sid,authenticated,name,value) "
                               "VALUES (%s,1,%s,%s)",
                               (username, "force_change_passwd", 1))
            db.commit()

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
            yield 'metanav', 'register', tag.a("Register",
                                               href=req.href.register())


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


class MessageWrapper(object):
    """Wrapper for add_warning and add_notice to work around the requirement
    for a % operator."""
    def __init__(self, body):
        self.body = body

    def __mod__(self, rhs):
        return self.body


class EmailVerificationNotification(SingleUserNofification):
    template_name = 'verify_email.txt'

    def notify(self, username, token):
        self.data.update({
            'account': {
                'username': username,
                'token': token,
            },
            'verify': {
                'link': self.env.abs_href.verify_email(token=token),
            }
        })

        projname = self.config.get('project', 'name')
        subject = '[%s] Trac email verification for user: %s' % (projname, username)

        SingleUserNofification.notify(self, username, subject)


class EmailVerificationModule(Component):
    implements(IRequestFilter, IRequestHandler)

    # IRequestFilter methods

    def pre_process_request(self, req, handler):
        if not req.session.authenticated:
            # Anonymous users should register and perms should be tweaked so
            # that anonymous users can't edit wiki pages and change or create
            # tickets. As such, this email verifying code won't be used on them
            return handler
        if handler is not self and 'email_verification_token' in req.session:
            chrome.add_warning(req, MessageWrapper(tag.span(
                    'Your permissions have been limited until you ',
                    tag.a(href=req.href.verify_email())(
                          'verify your email address'))))
            req.perm = perm.PermissionCache(self.env, 'anonymous')
        return handler

    def post_process_request(self, req, template, data, content_type):
        if not req.session.authenticated:
            # Anonymous users should register and perms should be tweaked so
            # that anonymous users can't edit wiki pages and change or create
            # tickets. As such, this email verifying code won't be used on them
            return template, data, content_type
        if req.session.get('email') != req.session.get('email_verification_sent_to'):
            req.session['email_verification_token'] = self._gen_token()
            req.session['email_verification_sent_to'] = req.session.get('email')
            self._send_email(req)
            chrome.add_notice(req, MessageWrapper(tag.span(
                    'An email has been sent to ', req.session['email'],
                    ' with a token to ',
                    tag.a(href=req.href.verify_email())(
                        'verify your new email address'))))
        return template, data, content_type

    # IRequestHandler methods

    def match_request(self, req):
        return req.path_info == '/verify_email'

    def process_request(self, req):
        if 'email_verification_token' not in req.session:
            chrome.add_notice(req, 'Your email is already verified')
        elif req.method != 'POST':
            pass
        elif 'resend' in req.args:
            self._send_email(req)
            chrome.add_notice(req,
                    'A notification email has been resent to %s.',
                    req.session.get('email'))
        elif 'verify' in req.args:
            if req.args['token'] == req.session['email_verification_token']:
                del req.session['email_verification_token']
                chrome.add_notice(req, 'Thank you for verifying your email address')
            else:
                chrome.add_warning(req, 'Invalid verification token')
        data = {}
        if 'token' in req.args:
            data['token'] = req.args['token']
        return 'verify_email.html', data, None

    def _gen_token(self):
        return base64.urlsafe_b64encode(urandom(6))

    def _send_email(self, req):
        notifier = EmailVerificationNotification(self.env)
        notifier.notify(req.authname, req.session['email_verification_token'])
