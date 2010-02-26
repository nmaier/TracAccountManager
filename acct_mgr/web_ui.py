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
import time

from trac import perm, util
from trac.core import *
from trac.config import IntOption, BoolOption
from trac.prefs import IPreferencePanelProvider
from trac.web import auth
from trac.web.api import IAuthenticator
from trac.web.main import IRequestHandler, IRequestFilter
from trac.web import chrome
from trac.web.chrome import INavigationContributor, ITemplateProvider
from genshi.core import Markup
from genshi.builder import tag

from api import AccountManager
from acct_mgr.util import urandom

def _create_user(req, env, check_permissions=True):
    mgr = AccountManager(env)

    user = req.args.get('user')
    name = req.args.get('name')
    email = req.args.get('email')
    acctmgr = {'username' : user,
               'name' : name,
               'email' : email,
              }
    error = TracError('')
    error.acctmgr = acctmgr
    if not user:
        error.message = 'Username cannot be empty.'
        raise error

    if mgr.has_user(user):
        error.message = 'Another account with that name already exists.'
        raise error

    if check_permissions:
        # disallow registration of accounts which have existing permissions
        permission_system = perm.PermissionSystem(env)
        if permission_system.get_user_permissions(user) != \
           permission_system.get_user_permissions('authenticated'):
            error.message = 'Another account with that name already exists.'
            raise error

    password = req.args.get('password')
    if not password:
        error.message = 'Password cannot be empty.'
        raise error

    if password != req.args.get('password_confirm'):
        error.message = 'The passwords must match.'
        raise error

    try:
        mgr.set_password(user, password)
    except TracError, e:
        e.acctmge = acctmgr
        raise e

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

    reset_password = BoolOption('account-manager', 'reset_password',
                                True, 'Set to false if there is no email '
                                'system setup.')

    def __init__(self):
        self._write_check(log=True)

    def _write_check(self, log=False):
        writable = AccountManager(self.env).get_all_supporting_stores('set_password')
        if not writable and log:
            self.log.warn('AccountModule is disabled because the password '
                          'store does not support writing.')
        return writable

    #IPreferencePanelProvider methods
    def get_preference_panels(self, req):
        writable = self._write_check()
        if not writable:
            return
        if req.authname and req.authname != 'anonymous':
            user_store = AccountManager(self.env).find_user_store(req.authname)
            if user_store in writable:
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
                if req.href(req.path_info) != redirect_url:
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
                and self.reset_password
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
                    chrome.add_notice(req, Markup(tag(
                        "Thank you for taking the time to update your password."
                    )))
                    force_change_password = False
            elif action == 'delete' and delete_enabled:
                data.update(self._do_delete(req))
            else:
                data.update({'error': 'Invalid action'})
        if force_change_password:
            chrome.add_warning(req, Markup(tag(
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

        new_password = self._random_password()
        mgr = AccountManager(self.env)
        try:
            mgr._notify('password_reset', username, email, new_password)
        except Exception, e:
            return {'error': ','.join(e.args)}
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
        data = {'acctmgr' : { 'username' : None,
                              'name' : None,
                              'email' : None,
                            },
                }
        if req.method == 'POST' and action == 'create':
            try:
                _create_user(req, self.env)
            except TracError, e:
                data['registration_error'] = e.message
                formdata = getattr(e, 'acctmgr', None)
                if formdata:
                    data['acctmgr'] = formdata
                else:
                    raise e
            else:
                req.redirect(req.href.login())
        data['reset_password_enabled'] = \
            (self.env.is_component_enabled(AccountModule)
             and AccountModule(self.env).reset_password)

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
                'reset_password_enabled': AccountModule(self.env).reset_password_enabled,
                'persistent_sessions': AccountManager(self.env).persistent_sessions
            }
            if req.method == 'POST':
                data['login_error'] = 'Invalid username or password'
            return 'login.html', data, None
        return auth.LoginModule.process_request(self, req)

    # overrides
    def _get_name_for_cookie(self, req, cookie):
        """Returns the user name for the current Trac session. Is called by
           authenticate() when the cookie 'trac_auth' is sent by the browser.
        """
        
        # Disable IP checking when a persistent session is available, as the
        # user may have a dynamic IP adress and this would lead to the user 
        # being logged out due to an IP address conflict.
        checkIPSetting = self.check_ip and \
                         AccountManager(self.env).persistent_sessions and \
                         'trac_auth_session' in req.incookie
        if checkIPSetting:
          self.env.config.set('trac', 'check_auth_ip', False)
        
        name = auth.LoginModule._get_name_for_cookie(self, req, cookie)
        
        if checkIPSetting:
          self.env.config.set('trac', 'check_auth_ip', True) # reenable ip checking
        
        if AccountManager(self.env).persistent_sessions and \
           name and \
           'trac_auth_session' in req.incookie:
            # Persistent sessions enabled, the user is logged in ('name' exists)
            # and has actually decided to use this feature (indicated by the '
            # trac_auth_session' cookie existing).
            # 
            # NOTE: This method is called on every request.
            
            # Update the timestamp of the session so that it doesn't expire
            self.env.log.debug('Updating session %s for user %s' %
                                (cookie.value, name))
                                
            # Refresh in database
            db = self.env.get_db_cnx()
            cursor = db.cursor()
            cursor.execute('UPDATE auth_cookie SET time=%s WHERE cookie=%s',
                            (int(time.time()), cookie.value))
            db.commit()
            
            # Refresh session cookie
            # TODO Change session id (cookie.value) now and then as it otherwise
            #   never would change at all (i.e. stay the same indefinitely and
            #   therefore is vulnerable to be hacked).
            req.outcookie['trac_auth'] = cookie.value
            req.outcookie['trac_auth']['path'] = req.base_path or '/'
            req.outcookie['trac_auth']['expires'] = 86400 * 30
            if self.env.secure_cookies:
                req.outcookie['trac_auth']['secure'] = True
                
            req.outcookie['trac_auth_session'] = 1
            req.outcookie['trac_auth_session']['path'] = req.base_path or '/'
            req.outcookie['trac_auth_session']['expires'] = 86400 * 30

        return name

    # overrides
    def _do_login(self, req):
        if not req.remote_user:
            req.redirect(self.env.abs_href())
        res = auth.LoginModule._do_login(self, req)
        if req.args.get('rememberme', '0') == '1':
            # Set the session to expire in 30 days (and not when to browser is
            # closed - what is the default).
            req.outcookie['trac_auth']['expires'] = 86400 * 30
            
            # This cookie is used to indicate that the user is actually using
            # the "Remember me" feature. This is necessary for 
            # '_get_name_for_cookie()'.
            req.outcookie['trac_auth_session'] = 1
            req.outcookie['trac_auth_session']['path'] = req.base_path or '/'
            req.outcookie['trac_auth_session']['expires'] = 86400 * 30
            
        return res

    # overrides
    def _do_logout(self, req):
        auth.LoginModule._do_logout(self, req)
        
        # Expire the persistent session cookie
        req.outcookie['trac_auth_session'] = ''
        req.outcookie['trac_auth_session']['path'] = req.base_path or '/'
        req.outcookie['trac_auth_session']['expires'] = -10000

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
            chrome.add_warning(req, Markup(tag.span(
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

        email = req.session.get('email')
        # Only send verification if the user actually entered en email address.
        if email and email != req.session.get('email_verification_sent_to'):
            req.session['email_verification_token'] = self._gen_token()
            req.session['email_verification_sent_to'] = email
            mgr = AccountManager(self.env)
            mgr._notify(
                'email_verification_requested', 
                req.authname, 
                req.session['email_verification_token']
            )
            chrome.add_notice(req, Markup(tag.span(
                    'An email has been sent to ', email,
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
            mgr = AccountManager(self.env)
            mgr._notify(
                'email_verification_requested', 
                req.authname, 
                req.session['email_verification_token']
            )
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
