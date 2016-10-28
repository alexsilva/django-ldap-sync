from django.core.management.base import BaseCommand
from ldap_sync.service import Service
from ldap_sync.utils import get_setting


class Command(BaseCommand):
    help = 'Tests whether the service is properly configured and functional.'

    def handle(self, *args, **options):
        user_filter = get_setting('LDAP_SYNC_USER_FILTER')
        user_attributes = get_setting('LDAP_SYNC_USER_ATTRIBUTES', strict=True)
        user_keys = set(user_attributes.keys())
        user_extra_attributes = get_setting('LDAP_SYNC_USER_EXTRA_ATTRIBUTES', default=[])
        user_keys.update(user_extra_attributes)

        uri = get_setting('LDAP_SYNC_URI', strict=True)
        base_user = get_setting('LDAP_SYNC_BASE_USER', strict=True)
        base_pass = get_setting('LDAP_SYNC_BASE_PASS', strict=True)
        base = get_setting('LDAP_SYNC_BASE', strict=True)

        service = Service(uri)
        service.login(base_user, base_pass)
        for user in service.search(base, user_filter, user_keys, Service.ObjectTypes.USERS):
            print user
