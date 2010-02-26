# -*- coding: utf-8 -*-
#
# Copyright (C) 2008 Pedro Algarvio <ufs@ufsoft.org>
#
# "THE BEER-WARE LICENSE" (Revision 42):
# <trac@matt-good.net> wrote this file.  As long as you retain this notice you
# can do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return.   Matthew Good
#
# Author: Pedro Algarvio <ufs@ufsoft.org>

import re

from trac import __version__
from trac.core import *
from trac.admin import IAdminPanelProvider
from trac.config import Option, ListOption
from trac.web.chrome import ITemplateProvider
from trac.notification import NotifyEmail
from trac.util.text import CRLF
from trac.util.translation import _


from pkg_resources import resource_filename

from api import IAccountChangeListener

class AccountChangeListener(Component):
    implements(IAccountChangeListener)

    _notify_actions = ListOption(
        'account-manager', 'notify_actions', [],
        doc="""Comma separated list of actions to notify of.
        Available actions 'new', 'change', 'delete'.""")

    # IAccountChangeListener methods

    def user_created(self, username, password):
        if 'new' in self._notify_actions:
            notifier = AccountChangeNotification(self.env)
            notifier.notify(username, 'New user registration')

    def user_password_changed(self, username, password):
        if 'change' in self._notify_actions:
            notifier = AccountChangeNotification(self.env)
            notifier.notify(username, 'Password reset for user')

    def user_deleted(self, username):
        if 'delete' in self._notify_actions:
            notifier = AccountChangeNotification(self.env)
            notifier.notify(username, 'Deleted User')

    def user_password_reset(self, username, email, password):
        notifier = PasswordResetNotification(self.env)
        if email != notifier.email_map.get(username):
            raise Exception('The email and username do not '
                            'match a known account.')
        notifier.notify(username, password)

    def user_email_verification_requested(self, username, token):
        notifier = EmailVerificationNotification(self.env)
        notifier.notify(username, token)

class AccountChangeNotification(NotifyEmail):
    template_name = 'user_changes_email.txt'

    _recipients = Option(
        'account-manager', 'account_changes_notify_addresses', '',
        """List of email addresses that get notified of user changes, ie,
        new user, password change and delete user.""")

    def get_recipients(self, resid):
        recipients = self._recipients.split()
        return (recipients,[])

    def notify(self, username, action):
        self.data.update({
            'account': {
                'username': username,
                'action': action
            },
            'login': {
                'link': self.env.abs_href.login(),
            }
        })

        projname = self.config.get('project', 'name')
        subject = '[%s] %s: %s' % (projname, action, username)

        NotifyEmail.notify(self, username, subject)

    def send(self, torcpts, ccrcpts, mime_headers={}):
        from email.MIMEText import MIMEText
        from email.Utils import formatdate
        stream = self.template.generate(**self.data)
        body = stream.render('text')
        projname = self.config.get('project', 'name')
        public_cc = self.config.getbool('notification', 'use_public_cc')
        headers = {}
        headers['X-Mailer'] = 'Trac %s, by Edgewall Software' % __version__
        headers['X-Trac-Version'] =  __version__
        headers['X-Trac-Project'] =  projname
        headers['X-URL'] = self.config.get('project', 'url')
        headers['Precedence'] = 'bulk'
        headers['Auto-Submitted'] = 'auto-generated'
        headers['Subject'] = self.subject
        headers['From'] = (self.from_name or projname, self.from_email)
        headers['Reply-To'] = self.replyto_email

        def build_addresses(rcpts):
            """Format and remove invalid addresses"""
            return filter(lambda x: x, \
                          [self.get_smtp_address(addr) for addr in rcpts])

        def remove_dup(rcpts, all):
            """Remove duplicates"""
            tmp = []
            for rcpt in rcpts:
                if not rcpt in all:
                    tmp.append(rcpt)
                    all.append(rcpt)
            return (tmp, all)

        toaddrs = build_addresses(torcpts)
        ccaddrs = build_addresses(ccrcpts)

        recipients = []
        (toaddrs, recipients) = remove_dup(toaddrs, recipients)
        (ccaddrs, recipients) = remove_dup(ccaddrs, recipients)

        # if there is not valid recipient, leave immediately
        if len(recipients) < 1:
            self.env.log.info('no recipient for account change notification')
            return

        pcc = []
        if public_cc:
            pcc += ccaddrs
            if toaddrs:
                headers['To'] = ', '.join(toaddrs)
        if pcc:
            headers['Cc'] = ', '.join(pcc)
        headers['Date'] = formatdate()
        # sanity check
        if not self._charset.body_encoding:
            try:
                dummy = body.encode('ascii')
            except UnicodeDecodeError:
                raise TracError(_("Ticket contains non-ASCII chars. " \
                                  "Please change encoding setting"))
        msg = MIMEText(body, 'plain')
        # Message class computes the wrong type from MIMEText constructor,
        # which does not take a Charset object as initializer. Reset the
        # encoding type to force a new, valid evaluation
        del msg['Content-Transfer-Encoding']
        msg.set_charset(self._charset)
        self.add_headers(msg, headers);
        self.add_headers(msg, mime_headers);
        self.env.log.info("Sending SMTP notification to %s:%d to %s"
                           % (self.smtp_server, self.smtp_port, recipients))
        msgtext = msg.as_string()
        # Ensure the message complies with RFC2822: use CRLF line endings
        recrlf = re.compile("\r?\n")
        msgtext = CRLF.join(recrlf.split(msgtext))
        self.server.sendmail(msg['From'], recipients, msgtext)


class SingleUserNotification(NotifyEmail):
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


class PasswordResetNotification(SingleUserNotification):
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

        SingleUserNotification.notify(self, username, subject)


class EmailVerificationNotification(SingleUserNotification):
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

        SingleUserNotification.notify(self, username, subject)


class AccountChangeNotificationAdminPanel(Component):
    implements(IAdminPanelProvider, ITemplateProvider)

    # IAdminPageProvider
    def get_admin_panels(self, req):
        if req.perm.has_permission('TRAC_ADMIN'):
            yield ('accounts', 'Accounts', 'notification', 'Notification')

    def render_admin_panel(self, req, cat, page, path_info):
        if page == 'notification':
            return self._do_config(req)

    def _do_config(self, req):
        if req.method == 'POST':
            self.config.set(
                'account-manager', 'account_changes_notify_addresses',
                ' '.join(req.args.get('notify_addresses').strip('\n').split()))

            self.config.set('account-manager', 'notify_actions',
                ','.join(req.args.getlist('notify_actions'))
                )
            self.config.save()
        notify_addresses = self.config.get(
            'account-manager', 'account_changes_notify_addresses').split()
        notify_actions = self.config.getlist('account-manager',
                                             'notify_actions')
        data = dict(notify_actions=notify_actions,
                    notify_addresses=notify_addresses)
        return 'admin_accountsnotification.html', data

    # ITemplateProvider
    def get_htdocs_dirs(self):
        return []

    def get_templates_dirs(self):
        return [resource_filename(__name__, 'templates')]
