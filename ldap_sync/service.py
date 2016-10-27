from ldap_sync.utils import get_setting
from django.utils.module_loading import import_string


class Service(object):
    """Interface"""

    class ObjectTypes(object):
        GROUPS = "groups"
        USERS = "users"

    def __init__(self, uri):
        self.uri = uri

    def search(self, base, filter, attributes, objectype=None):
        """Make a search"""
        raise NotImplemented

    def login(self, username, password):
        """bind"""
        raise NotImplemented

# External service implementation.
service_string = get_setting("LDAP_SYNC_SERVICE", default=None)

if isinstance(service_string, basestring):
    Service = import_string(service_string)
