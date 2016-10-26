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


if sys.platform.startswith("win"):
    import pyad


    class PyadService(Service):

        def search(self, base, filter, attributes):
            """"""

        def login(self, username, password):
            self.ldap.set_defaults(username=username, password=password)

        def __call__(self, uri, *args, **kwargs):
            self.ldap.set_defaults(ldap_server=uri)


    service = PyadService(pyad)
else:

    raise NotImplemented
