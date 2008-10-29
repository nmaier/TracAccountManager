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

def _setorder(req, stores):
    """Pull the password store ordering out of the req object"""
    for store in stores.get_all_stores():
        stores[store] = int(req.args.get(store.__class__.__name__, 0))
        continue

class StoreOrder(dict):
    """Keeps the order of the Password Stores"""

    instance = 0

    def __init__(self, d={}, stores=[], list=[]):
        self.instance += 1
        self.d = {}
        self.sxref = {}
        for store in stores:
            self.d[store] = 0
            self[0] = store
            self.sxref[store.__class__.__name__] = store
            continue
        for i, s in enumerate(list):
            self.d[s] = i + 1
            self[i + 1] = s

    def __getitem__(self, key):
        """Lookup a store in the list"""
        return self.d[key]

    def __setitem__(self, key, value):
        if isinstance(key, Component):
            order = self.d[key]
            self.d[key] = value
            self.d[order].remove(key)
            self[value] = key
        elif isinstance(key, basestring):
            self.d[self.sxref[key]] = value
        elif isinstance(key, int):
            self.d.setdefault(key, [])
            self.d[key].append(value)
        else:
            raise KeyError('Invalid key type (%s) for StoreOrder'
                           % str(type(key)))
        pass

    def get_enabled_stores(self):
        """Return an ordered list of password stores

        All stores that are order 0 are dropped from the list.
        """
        keys = [k for k in self.d.keys() if isinstance(k, int)]
        keys.sort()
        storelist = []
        for k in keys[1:]:
            storelist.extend(self.d[k])
            continue
        return storelist

    def get_enabled_store_names(self):
        """Returns the class names of the enabled password stores"""
        stores = self.get_enabled_stores()
        return [s.__class__.__name__ for s in stores]

    def get_all_stores(self):
        return [k for k in self.d.keys() if isinstance(k, Component)]

    def numstores(self):
        return len(self.get_all_stores())


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
        stores = StoreOrder(stores=self.account_manager.stores,
                            list=self.account_manager.password_store)
        if req.method == 'POST':
            _setorder(req, stores)
            self.config.set('account-manager', 'password_store',
                            ','.join(stores.get_enabled_store_names()))
            for store in stores.get_all_stores():
                for attr, option in _getoptions(store):
                    newvalue = req.args.get('%s.%s' % (store.__class__.__name__, attr))
                    self.log.debug("%s.%s: %s" % (store.__class__.__name__, attr, newvalue))
                    if newvalue is not None:
                        self.config.set(option.section, option.name, newvalue)
                        self.config.save()
            self.config.set('account-manager', 'force_passwd_change',
                            req.args.get('force_passwd_change'))
            self.config.save()
        sections = []
        for store in self.account_manager.stores:
            options = []
            for attr, option in _getoptions(store):
                opt_val = option.__get__(store, store)
                opt_val = isinstance(opt_val, Component) and \
                          opt_val.__class__.__name__ or opt_val
                options.append(
                            {'label': attr,
                            'name': '%s.%s' % (store.__class__.__name__, attr),
                            'value': opt_val,
                            })
                continue
            sections.append(
                        {'name': store.__class__.__name__,
                        'classname': store.__class__.__name__,
                        'order': stores[store],
                        'options' : options,
                        })
            continue
        sections = sorted(sections, key=lambda i: i['name'])
        numstores = range(0, stores.numstores() + 1)
        data = {'sections': sections,
                'numstores': numstores,
                'force_passwd_change': self.account_manager.force_passwd_change}
        return 'admin_accountsconfig.html', data

    def _do_users(self, req):
        perm = PermissionSystem(self.env)
        listing_enabled = self.account_manager.supports('get_users')
        create_enabled = self.account_manager.supports('set_password')
        password_change_enabled = self.account_manager.supports('set_password')
        delete_enabled = self.account_manager.supports('delete_user')

        data = {
            'listing_enabled': listing_enabled,
            'create_enabled': create_enabled,
            'delete_enabled': delete_enabled,
            'password_change_enabled': password_change_enabled,
            'acctmgr' : { 'username' : None,
                          'name' : None,
                          'email' : None,
                        }
        }

        if req.method == 'POST':
            if req.args.get('add'):
                if create_enabled:
                    try:
                        _create_user(req, self.env, check_permissions=False)
                    except TracError, e:
                        data['registration_error'] = e.message
                        data['acctmgr'] = e.acctmgr
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
            elif req.args.get('change'):
                if password_change_enabled:
                    try:
                        user = req.args.get('change_user')
                        acctmgr = { 'change_username' : user,
                        }
                        error = TracError('')
                        error.acctmgr = acctmgr
                        if not user:
                            error.message = 'Username cannot be empty.'
                            raise error

                        password = req.args.get('change_password')
                        if not password:
                            error.message = 'Password cannot be empty.'
                            raise error

                        if password != req.args.get('change_password_confirm'):
                            error.message = 'The passwords must match.'
                            raise error

                        self.account_manager.set_password(user, password)
                    except TracError, e:
                        data['password_change_error'] = e.message
                        data['acctmgr'] = getattr(e, 'acctmgr', '')
                else:
                    data['password_change_error'] = 'The password store does not ' \
                                                    'support changing passwords'
            

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
