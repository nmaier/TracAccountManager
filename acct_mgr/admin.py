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

import inspect

from trac.core import *
from trac.config import Option
from trac.perm import PermissionSystem
from trac.util import sorted
from trac.util.datefmt import format_datetime
from trac.web.chrome import ITemplateProvider
from trac.admin import IAdminPanelProvider

from acct_mgr.api import AccountManager
from acct_mgr.web_ui import _create_user

def _getoptions(cls):
    if isinstance(cls, Component):
        cls = cls.__class__
    return [(name, value) for name, value in inspect.getmembers(cls)
            if isinstance(value, Option)]

class AccountManagerAdminPage(Component):

    implements(IAdminPanelProvider, ITemplateProvider)

    def __init__(self):
        self.account_manager = AccountManager(self.env)

    # IAdminPageProvider
    def get_admin_panels(self, req):
        if req.perm.has_permission('TRAC_ADMIN'):
            yield ('accounts', 'Accounts', 'config', 'Configuration')
            yield ('accounts', 'Accounts', 'users', 'Users')

    def render_admin_panel(self, req, cat, page, path_info):
        if page == 'config':
            return self._do_config(req)
        elif page == 'users':
            return self._do_users(req)

    def _do_config(self, req):
        if req.method == 'POST':
            selected_class = req.args.get('selected')
            self.config.set('account-manager', 'password_store', selected_class)
            selected = self.account_manager.password_store
            for attr, option in _getoptions(selected):
                newvalue = req.args.get('%s.%s' % (selected_class, attr))
                if newvalue is not None:
                    self.config.set(option.section, option.name, newvalue)
                    self.config.save()
        try:
            selected = self.account_manager.password_store
        except AttributeError:
            selected = None
        sections = [
            {'name': store.__class__.__name__,
             'classname': store.__class__.__name__,
             'selected': store is selected,
             'options': [
                {'label': attr,
                 'name': '%s.%s' % (store.__class__.__name__, attr),
                 'value': option.__get__(store, store),
                }
                for attr, option in _getoptions(store)
             ],
            } for store in self.account_manager.stores
        ]
        sections = sorted(sections, key=lambda i: i['name'])
        return 'admin_accountsconfig.html', {'sections': sections}

    def _do_users(self, req):
        perm = PermissionSystem(self.env)
        listing_enabled = self.account_manager.supports('get_users')
        create_enabled = self.account_manager.supports('set_password')
        delete_enabled = self.account_manager.supports('delete_user')

        data = {
            'listing_enabled': listing_enabled,
            'create_enabled': create_enabled,
            'delete_enabled': delete_enabled,
        }

        if req.method == 'POST':
            if req.args.get('add'):
                if create_enabled:
                    try:
                        _create_user(req, self.env, check_permissions=False)
                    except TracError, e:
                        data['registration_error'] = e.message
                else:
                    data['registration_error'] = 'The password store does ' \
                                                 'not support creating users'
            elif req.args.get('remove'):
                if delete_enabled:
                    sel = req.args.get('sel')
                    sel = isinstance(sel, list) and sel or [sel]
                    for account in sel:
                        self.account_manager.delete_user(account)
                else:
                    data['deletion_error'] = 'The password store does not ' \
                                             'support deleting users'

        if listing_enabled:
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
            cursor.execute("SELECT sid,last_visit FROM session WHERE "
                           "authenticated=1")
            for username, last_visit in cursor:
                account = accounts.get(username)
                if account and last_visit:
                    account['last_visit'] = format_datetime(last_visit)

            data['accounts'] = sorted(accounts.itervalues(),
                                      key=lambda acct: acct['username'])

        return 'admin_users.html', data

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
