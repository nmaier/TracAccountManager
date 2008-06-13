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

from trac.tests.notification import SMTPThreadedServer, SMTPServerStore       
        
class NonForgetingSMTPServerStore(SMTPServerStore):
    """
    Non forgetting store for SMTP data.
    """
    # We override trac's implementation of a mailstore because if forgets
    # the last message when a new one arrives.
    # Account Manager at times sends more than one email and we need to be
    # able to test both
     
    sender = None
    message = None
    recipients = None
    
    messages = {}
    def reset(self, args):
        if self.message:
            for recipient in self.recipients:
                self.messages[recipient] = {}
                self.messages[recipient]['recipients'] = self.recipients                
                self.messages[recipient]['sender'] = self.sender                
                self.messages[recipient]['message'] = self.message
        self.sender = None
        self.recipients = []
        self.message = None
        
    def full_reset(self):
        self.messages = {}
        self.sender = None
        self.recipients = []
        self.message = None

class AcctMgrSMTPThreadedServer(SMTPThreadedServer):
    """
    Run a SMTP server for a single connection, within a dedicated thread
    """
    
    # We override trac's SMTPThreadedServer in order to use our own mail store

    def __init__(self, port):
        SMTPThreadedServer.__init__(self, port)
        # Override the store with out own
        self.store  = NonForgetingSMTPServerStore()

    def get_sender(self, recipient=None):
        """Return the sender of a message. If recipient is passed, return
        the sender for the message sent to that recipient, else, send
        the sender for last message"""
        try:
            return self.store.messages[recipient]['sender']
        except KeyError:
            return self.store.sender

    def get_recipients(self, recipient=None):
        """Return the recipients of a message. If recipient is passed, return
        the recipients for the message sent to that recipient, else, send
        recipients for last message"""
        try:
            return self.store.messages[recipient]['recipients']
        except KeyError:
            return self.store.recipients
    def get_message(self, recipient=None):
        """Return the message of a message. If recipient is passed, return
        the actual message for the message sent to that recipient, else, send
        the last message"""
        try:
            return self.store.messages[recipient]['message']
        except KeyError:
            return self.store.message
    
    def get_message_parts(self, recipient):
        """Return the message parts(dict). If recipient is passed, return
        the parts for the message sent to that recipient, else, send the parts
        for last message"""
        try:
            return self.store.messages[recipient]
        except KeyError:
            return None
        
    def full_reset(self):
        self.store.full_reset()
        
        
