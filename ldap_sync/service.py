class LdapSearchException(Exception):
    """"""


class LdapSearch(object):
    """User search interface and ldap groups"""

    def __init__(self, uri):
        self.uri = uri

    def users(self, sbase, sfilter, attributes):
        """Make a search user"""
        raise NotImplementedError

    def groups(self, sbase, sfilter, attributes):
        """Make a search group"""
        raise NotImplementedError

    def login(self, username, password):
        """bind"""
        raise NotImplementedError
