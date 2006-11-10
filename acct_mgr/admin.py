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

from trac.core import *
from trac.perm import PermissionSystem
from trac.util import sorted
from trac.util.datefmt import format_datetime
from trac.admin import IAdminPanelProvider

from acct_mgr.api import AccountManager
from acct_mgr.web_ui import _create_user

class AccountManagerAdminPage(Component):

    implements(IAdminPanelProvider)

    def __init__(self):
        self.account_manager = AccountManager(self.env)

    # IAdminPageProvider
    def get_admin_panels(self, req):
        if req.perm.has_permission('TRAC_ADMIN'):
            yield ('general', 'General', 'accounts', 'Accounts')

    def render_admin_panel(self, req, cat, page, path_info):
        perm = PermissionSystem(self.env)
        data = {}
        if req.method == 'POST':
            if req.args.get('add'):
                try:
                    _create_user(req, self.env, check_permissions=False)
                except TracError, e:
                    data['registration_error'] = e.message
            elif req.args.get('remove'):
                sel = req.args.get('sel')
                sel = isinstance(sel, list) and sel or [sel]
                for account in sel:
                    self.account_manager.delete_user(account)

        accounts = {}
        for username in self.account_manager.get_users():
            accounts[username] = {'username': username}

        for username, name, email in self.env.get_known_users():
            account = accounts.get(username)
            if account:
                account['name'] = name
                account['email'] = email

        db = self.env.get_db_cnx()
        cursor = db.cursor()
        cursor.execute("SELECT sid,last_visit FROM session WHERE authenticated=1")
        for username, last_visit in cursor:
            account = accounts.get(username)
            if account and last_visit:
                account['last_visit'] = format_datetime(last_visit)

        data['accounts'] = sorted(accounts.itervalues(),
                                  key=lambda acct: acct['username'])

        return 'admin_accounts.html', data

