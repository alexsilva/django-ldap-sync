import sys


class Service(object):
    """Interface"""

    def __init__(self, ldap):
        self.ldap = ldap

    def search(self, base, filter, attributes):
        """Make a search"""
        raise NotImplemented

    def login(self, username, password):
        """Make login"""
        raise NotImplemented

    def __call__(self, uri, username=None, password=None, *args, **kwargs):
        raise NotImplemented
