import os
import sys

from trac.env import Environment
from acct_mgr.api import AccountManager
from acct_mgr.htfile import HtPasswdStore, HtDigestStore
from acct_mgr.pwhash import HtPasswdHashMethod, HtDigestHashMethod

env = Environment(sys.argv[1])

store = AccountManager(env).password_store
if isinstance(store, HtPasswdStore):
    env.config.set('account-manager', 'hash_method', 'HtPasswdHashMethod')
    prefix = ''
elif isinstance(store, HtDigestStore):
    env.config.set('account-manager', 'hash_method', 'HtDigestHashMethod')
    prefix = store.realm + ':'
else:
    print >>sys.stderr, 'Unsupported password store:', store.__class__.__name__
    sys.exit(1)

password_file = os.path.join(env.path, env.config.get('account-manager',
                                                      'password_file'))
hashes = [line.strip().split(':', 1) for line in open(password_file)]
hashes = [(u,p) for u,p in hashes if p.startswith(prefix)]
if hashes:
    db = env.get_db_cnx()
    cursor = db.cursor()
    cursor.executemany("INSERT INTO session_attribute "
                       "(sid,authenticated,name,value) "
                       "VALUES (%s,1,'password',%s)",
                       hashes)
    db.commit()

env.config.set('account-manager', 'password_store', 'SessionStore')
env.config.save()
