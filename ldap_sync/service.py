import sys


class Service(object):
    """Interface"""

    class ObjectTypes(object):
        GROUPS = "groups"
        USERS = "users"

    def __init__(self, uri):
        pyad.set_defaults(ldap_server=uri)

    def search(self, base, filter, attributes, objectype=None):
        """Make a search"""
        raise NotImplemented

    def login(self, username, password):
        """bind"""
        raise NotImplemented


if sys.platform.startswith("win"):
    from pyad import *


    class PyadService(Service):
        """Interface implementation"""

        def _search_users(self, base, filter, attributes):
            """Search for users"""
            groups = adgroup.ADGroup.from_dn(filter + "," + base)
            users = []
            for user in groups.get_members():
                users.append((user.cn, {k: (getattr(user, k),) for k in attributes}))
            return users

        def _search_groups(self, base, filter, attributes):
            return []

        def search(self, base, filter, attributes, objectype=None):
            """generic search"""
            return getattr(self, '_search_' + objectype)(base, filter, attributes)

        def login(self, username, password):
            """make login"""
            pyad.set_defaults(username=username, password=password)


    Service = PyadService
else:

    raise NotImplemented
