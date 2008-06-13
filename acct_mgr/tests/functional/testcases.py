# -*- coding: utf-8 -*-
#
# Copyright (C) 2008 Matthew Good <trac@matt-good.net>
#
# "THE BEER-WARE LICENSE" (Revision 42):
# <trac@matt-good.net> wrote this file.  As long as you retain this notice you
# can do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return.   Matthew Good
#
# Author: Pedro Algarvio <ufs@ufsoft.org>

import base64

from trac.tests.notification import parse_smtp_message

from acct_mgr.tests.functional import *


class TestFormLoginAdmin(FunctionalTwillTestCaseSetup):
    def runTest(self):
        """Login with test user 'admin'"""
        self._tester.login('admin')
        self._tester.logout()

class TestFormLoginUser(FunctionalTwillTestCaseSetup):
    def runTest(self):
        """Login with test user 'user'"""
        self._tester.login('user')
        self._tester.logout()

class TestRegisterNewUser(FunctionalTestCaseSetup):
    def runTest(self):
        """Register 'testuser'"""
        self._tester.register('testuser')

class TestLoginNewUser(FunctionalTestCaseSetup):
    def runTest(self):
        """Login just registered 'testuser'"""
        self._tester.login('testuser')
        self._tester.logout()


class TestFailRegisterPasswdConfirmNotPassed(FunctionalTestCaseSetup):
    def runTest(self):
        """Fail if no password confirmation is passed"""
        reg_form_name = 'acctmgr_registerform'     
        username = 'testuser1'   
        tc.find("Register")
        tc.follow("Register")        
        tc.formvalue(reg_form_name, 'user', username)
        tc.formvalue(reg_form_name, 'password', username)
        tc.submit()
        tc.find("The passwords must match.")

class TestFailRegisterDuplicateUsername(FunctionalTestCaseSetup):
    def runTest(self):
        """Fail if username exists"""
        reg_form_name = 'acctmgr_registerform'
        username = 'testuser'   
        tc.find("Register")
        tc.follow("Register")        
        tc.formvalue(reg_form_name, 'user', username)
        tc.formvalue(reg_form_name, 'password', username)
        tc.formvalue(reg_form_name, 'password_confirm', username)
        tc.submit()
        tc.find("Another account with that name already exists.")
        
class TestNewAccountNotification(FunctionalTestCaseSetup):
    def runTest(self):
        """Send out notification on new account registrations"""
        tc.notfind('Logout')
        address_to_notify = 'admin@testenv%s.tld' % self._testenv.port
        new_username = 'foo'
        new_username_email = "foo@%s" % address_to_notify.split('@')[1]
         
        env = self._testenv.get_trac_environment()
        env.config.set('account-manager', 'account_changes_notify_addresses',
                       address_to_notify)
        env.config.set('account-manager', 'notify_actions', 'new,change,delete')
        env.config.set('account-manager', 'force_passwd_change', 'true')
        env.config.save()
        self._tester.register(new_username, new_username_email)
        
        headers, body = parse_smtp_message(self._smtpd.get_message())
        
        self.assertEqual(self._smtpd.get_recipients(), [address_to_notify])
        self.assertEqual(headers['Subject'],
                         '[%s] New user registration: %s' % (
                                            'testenv%s' % self._testenv.port,
                                            new_username))
        self.assertEqual(headers['X-URL'], self._testenv.url)
        
class TestNewAccountEmailVerification(FunctionalTestCaseSetup):
    def runTest(self):
        """User is shown info that he needs to verify his address"""
        user_email = "foo@testenv%s.tld" % self._testenv.port
        self._tester.login("foo")
        
        tc.find('<strong>Notice:</strong> <span>An email has been sent to '
                '%s with a token to <a href="/verify_email">verify your new '
                'email address</a></span>' % user_email)
        self._tester.go_to_front()
        tc.find('<strong>Warning:</strong> <span>Your permissions have been '
                'limited until you <a href="/verify_email">verify your email '
                'address</a></span>')
        
class VerifyNewAccountEmailAddress(FunctionalTestCaseSetup):
    def runTest(self):
        """User confirms his address with mailed token"""
        headers, body = parse_smtp_message(self._smtpd.get_message())
        blines = base64.decodestring(body).splitlines()
        token = [l.split() for l in blines if 'Verification Token' in l][0][-1]
        
        tc.find('Logout') # User is logged in from previous test
        self._tester.go_to_front()
        tc.find('<strong>Warning:</strong> <span>Your permissions have been '
                'limited until you <a href="/verify_email">verify your email '
                'address</a></span>')
        tc.go(self._testenv.url + '/verify_email')
        
        reg_form_name = 'acctmgr_verify_email'
        tc.formvalue(reg_form_name, 'token', token)
        tc.submit('verify')
        
        tc.notfind('<strong>Warning:</strong> <span>Your permissions have been '
                   'limited until you <a href="/verify_email">verify your email'
                   ' address</a></span>')
        tc.find('Thank you for verifying your email address')
        self._tester.go_to_front()
  
        
class PasswdResetsNotifiesAdmin(FunctionalTestCaseSetup):
    def runTest(self):
        """User password resets notifies admin by mail"""
        self._tester.logout()
        self._smtpd.full_reset() # Clean all previous sent emails
        tc.notfind('Logout')
        # Goto Login
        tc.find("Login")
        tc.follow("Login")
        # Do we have the Forgot passwd link
        tc.find('Forgot your password?')
        tc.follow('Forgot your password?')
        
        username = "foo"
        email_addr = "foo@testenv%s.tld" % self._testenv.port
        
        reset_form_name = 'acctmgr_passwd_reset'
        tc.formvalue(reset_form_name, 'username', username)
        tc.formvalue(reset_form_name, 'email', email_addr)
        tc.submit()
        
        headers, body = parse_smtp_message(
            self._smtpd.get_message('admin@testenv%s.tld' % self._testenv.port))
        self.assertEqual(headers['Subject'],
                         '[%s] Password reset for user: %s' % (
                                            'testenv%s' % self._testenv.port,
                                            username))
        self.assertEqual(headers['X-URL'], self._testenv.url)
        
        
class PasswdResetsNotifiesUser(FunctionalTestCaseSetup):
    def runTest(self):
        """Password reset sends new password to user by mail"""
        username = "foo"
        email_addr = "foo@testenv%s.tld" % self._testenv.port
        headers, self.body = parse_smtp_message(self._smtpd.get_message(email_addr))
        self.assertEqual(headers['Subject'],
                         '[%s] Trac password reset for user: %s' % (
                                            'testenv%s' % self._testenv.port,
                                            username))
        
class UserLoginWithMailedPassword(PasswdResetsNotifiesUser):
    def runTest(self):
        """User is able to login with the new password"""
        PasswdResetsNotifiesUser.runTest(self)
        # Does it include a new password
        body = base64.decodestring(self.body)
        username = 'foo'
        self.assertTrue('Username: %s' % username in body)
        self.assertTrue('Password:' in body)
        
        passwd = [l.split(':')[1].strip() for l in
                  body.splitlines() if 'Password:' in l][0]
        
        self._tester.login(username, passwd)
        
class UserIsForcedToChangePassword(FunctionalTestCaseSetup):
    def runTest(self):
        """User is forced to change password after resets"""
        tc.find('Logout')
        tc.find("You are required to change password because of a recent "
                "password change request.")
        

class UserCantBrowseUntilPasswdChange(PasswdResetsNotifiesUser):
    def runTest(self):
        """User can't navigate out of '/prefs/account' before password change"""
        PasswdResetsNotifiesUser.runTest(self)
        tc.find('Logout')
        forced_passwd_change_url = '^%s/prefs/account$' % self._tester.url
        tc.follow('Roadmap')
        tc.url(forced_passwd_change_url)
        tc.follow('View Tickets')
        tc.url(forced_passwd_change_url)
        tc.follow('New Ticket')
        tc.url(forced_passwd_change_url)
        tc.follow('Browse Source')
        tc.url(forced_passwd_change_url)
        
        # Now, let's change his password
        body = base64.decodestring(self.body)
        passwd = [l.split(':')[1].strip() for l in
                  body.splitlines() if 'Password:' in l][0]
        username = 'foo'
        change_passwd_form = 'userprefs'
        tc.formvalue(change_passwd_form, 'old_password', passwd)
        tc.formvalue(change_passwd_form, 'password', username)
        tc.formvalue(change_passwd_form, 'password_confirm', username)
        tc.submit()
        
        tc.notfind("You are required to change password because of a recent "
                   "password change request.")
        tc.find("Thank you for taking the time to update your password.")
        
        # We can now browse away from /prefs/accounts
        tc.follow('Roadmap')
        tc.url(self._tester.url + '/roadmap')
        # Clear the mailstore
        self._smtpd.full_reset()
        
class DeleteAccountNotifiesAdmin(FunctionalTestCaseSetup):
    def runTest(self):
        """Delete account notifies admin"""
        tc.find("Logout") # We're logged-in from previous post
        tc.follow("Preferences")
        tc.follow("Account")
        tc.url(self._testenv.url + '/prefs/account')
        
        delete_account_form_name = 'acctmgr_delete_account'
        tc.formvalue(delete_account_form_name, 'password', 'foo')
        tc.submit()
        tc.find("Login") # We're logged out when we delete our account
        headers, _ = parse_smtp_message(self._smtpd.get_message())
        self.assertEqual(headers['Subject'],
                         '[%s] Deleted User: %s' % (
                                'testenv%s' % self._testenv.port, 'foo'))
        
class UserNoLongerLogins(FunctionalTestCaseSetup):
    def runTest(self):
        """Deleted user can't login"""
        tc.follow('Login')
        login_form_name = 'acctmgr_loginform'
        tc.formvalue(login_form_name, 'user', 'foo')
        tc.formvalue(login_form_name, 'password', 'foo')
        tc.submit()
        tc.find("Invalid username or password")
        tc.notfind('Logout')
        
class UserIsAbleToRegisterWithSameUserName(FunctionalTestCaseSetup):
    def runTest(self):
        """Register with deleted username (session and session_attributes clean)"""
        self._tester.register('foo')
        self._tester.login('foo')
        self._tester.logout()
        self._smtpd.full_reset()

class NoEmailVerificationForAnonymousUsers(FunctionalTestCaseSetup):
    def runTest(self):
        """Anonymous users don't get their email address verified"""
        tc.find("Login")
        tc.follow("Preferences")
        form_name = 'userprefs'
        email_address = 'anonyous.user@fakedomain.tld'
        tc.formvalue(form_name, 'email', email_address)
        tc.submit()
        tc.notfind('<strong>Notice:</strong> <span>An email has been sent to '
                   '%s with a token to <a href="/verify_email">verify your new '
                   'email address</a></span>' % email_address)
        self._tester.go_to_front()
        tc.notfind('<strong>Warning:</strong> <span>Your permissions have been '
                   'limited until you <a href="/verify_email">verify your email '
                   'address</a></span>')
        
        
def suite():
    suite = FunctionalTestSuite()
    suite.addTest(TestFormLoginAdmin())
    suite.addTest(TestFormLoginUser())
    suite.addTest(TestRegisterNewUser())
    suite.addTest(TestLoginNewUser())
    suite.addTest(TestFailRegisterPasswdConfirmNotPassed())
    suite.addTest(TestFailRegisterDuplicateUsername())
    suite.addTest(TestNewAccountNotification())
    suite.addTest(TestNewAccountEmailVerification())
    suite.addTest(VerifyNewAccountEmailAddress())
    suite.addTest(PasswdResetsNotifiesAdmin())
    suite.addTest(PasswdResetsNotifiesUser())
    suite.addTest(UserLoginWithMailedPassword())
    suite.addTest(UserIsForcedToChangePassword())
    suite.addTest(UserCantBrowseUntilPasswdChange())
    suite.addTest(DeleteAccountNotifiesAdmin())
    suite.addTest(UserNoLongerLogins())
    suite.addTest(UserIsAbleToRegisterWithSameUserName())
    suite.addTest(NoEmailVerificationForAnonymousUsers())
    return suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')

