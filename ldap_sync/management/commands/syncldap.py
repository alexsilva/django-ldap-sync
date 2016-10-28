import logging

from django.core.exceptions import ImproperlyConfigured
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db import DataError
from django.db import IntegrityError
from django.utils.module_loading import import_string
from ldap_sync.service import Service
from ldap_sync.utils import get_setting


logger = logging.getLogger(__name__)


class Command(BaseCommand):
    can_import_settings = True
    help = 'Synchronize users and groups from an authoritative LDAP server'

    def handle(self, *args, **options):
        ldap_groups = self.get_ldap_groups()
        if ldap_groups:
            self.sync_ldap_groups(ldap_groups)

        ldap_users = self.get_ldap_users()
        self.sync_ldap_users(ldap_users)

    def get_ldap_users(self):
        """Retrieve user data from LDAP server."""
        user_filter = get_setting('LDAP_SYNC_USER_FILTER')
        if not user_filter:
            logger.debug('LDAP_SYNC_USER_FILTER not configured, skipping user sync')
            return None

        user_attributes = get_setting('LDAP_SYNC_USER_ATTRIBUTES', strict=True)
        user_keys = set(user_attributes.keys())
        user_extra_attributes = get_setting('LDAP_SYNC_USER_EXTRA_ATTRIBUTES', default=[])
        user_keys.update(user_extra_attributes)

        users = self.ldap_search(user_filter, user_keys,
                                 Service.ObjectTypes.USERS)
        logger.debug("Retrieved %d users" % len(users))
        return users

    def sync_ldap_users(self, ldap_users):
        """Synchronize users with local user model."""
        model = get_user_model()
        user_attributes = get_setting('LDAP_SYNC_USER_ATTRIBUTES')
        removed_user_groups = get_setting('LDAP_SYNC_REMOVED_USER_GROUPS', default=[])
        username_callbacks = get_setting('LDAP_SYNC_USERNAME_CALLBACKS', default=[
            'ldap_sync.encoder.hash_md5'
        ])
        username_field = get_setting('LDAP_SYNC_USERNAME_FIELD')
        if username_field is None:
            username_field = getattr(model, 'USERNAME_FIELD', 'username')
        user_callbacks = list(get_setting('LDAP_SYNC_USER_CALLBACKS', default=[]))
        removed_user_callbacks = list(get_setting('LDAP_SYNC_REMOVED_USER_CALLBACKS', default=[]))
        ldap_usernames = set()

        if not model._meta.get_field(username_field).unique:
            raise ImproperlyConfigured("Field '%s' must be unique" % username_field)

        if username_field not in user_attributes.values():
            error_msg = ("LDAP_SYNC_USER_ATTRIBUTES must contain the field '%s'" % username_field)
            raise ImproperlyConfigured(error_msg)

        for cname, attributes in ldap_users:
            defaults = {}
            try:
                for name, attribute in attributes.items():
                    try:
                        if isinstance(attribute[0], basestring):
                            value = attribute[0].decode('utf-8')
                        else:
                            value = attribute[0]
                        defaults[user_attributes[name]] = value
                    except KeyError:
                        pass
            except AttributeError:
                # In some cases attributes is a list instead of a dict; skip these invalid users
                continue

            try:
                username = defaults[username_field]
            except KeyError:
                logger.warning("User is missing a required attribute '%s'" % username_field)
                continue

            # username changes
            for path in username_callbacks:
                callback = import_string(path)
                username = callback(username, prefix=u','.join(removed_user_groups))
                defaults[username_field] = username

            kwargs = {
                username_field + '__exact': username,
                'defaults': defaults,
            }

            try:
                user, created = model.objects.get_or_create(**kwargs)
            except (IntegrityError, DataError) as e:
                logger.error("Error creating user %s: %s" % (username, e))
            else:
                if removed_user_groups:
                    # Add the groups that separate the ldap users
                    for group in Group.objects.filter(name__in=removed_user_groups):
                        user.groups.add(group)
                updated = False
                if created:
                    logger.debug("Created user %s" % username)
                    user.set_unusable_password()
                else:
                    for name, attr in defaults.items():
                        current_attr = getattr(user, name, None)
                        if current_attr != attr:
                            setattr(user, name, attr)
                            updated = True
                    if updated:
                        logger.debug("Updated user %s" % username)

                for path in user_callbacks:
                    callback = import_string(path)
                    callback(user, attributes, created, updated)

                user.save()

                if removed_user_callbacks:
                    ldap_usernames.add(username)

        if removed_user_callbacks:
            if not removed_user_groups:
                users = model.objects.values_list(username_field, flat=True)
            else:
                users = model.objects.filter(groups__name__in=removed_user_groups)\
                    .values_list(username_field, flat=True)
            django_usernames = set(users)
            for username in django_usernames - ldap_usernames:
                user = model.objects.get(**{username_field: username})
                for path in removed_user_callbacks:
                    callback = import_string(path)
                    callback(user)
                    logger.debug("Called %s for user %s" % (path, username))

        logger.info("Users are synchronized")

    def get_ldap_groups(self):
        """Retrieve groups from LDAP server."""
        group_filter = get_setting('LDAP_SYNC_GROUP_FILTER')
        if not group_filter:
            logger.debug('LDAP_SYNC_GROUP_FILTER not configured, skipping group sync')
            return None

        group_attributes = get_setting('LDAP_SYNC_GROUP_ATTRIBUTES', strict=True)

        groups = self.ldap_search(group_filter, group_attributes.keys(),
                                  Service.ObjectTypes.GROUPS)
        logger.debug("Retrieved %d groups" % len(groups))
        return groups

    def sync_ldap_groups(self, ldap_groups):
        """Synchronize LDAP groups with local group model."""
        group_attributes = get_setting('LDAP_SYNC_GROUP_ATTRIBUTES')
        groupname_field = 'name'

        if groupname_field not in group_attributes.values():
            error_msg = "LDAP_SYNC_GROUP_ATTRIBUTES must contain the field '%s'" % groupname_field
            raise ImproperlyConfigured(error_msg)

        for cname, ldap_attributes in ldap_groups:
            defaults = {}
            try:
                for name, attribute in ldap_attributes.items():
                    if isinstance(attribute[0], basestring):
                        value = attribute[0].decode('utf-8')
                    else:
                        value = attribute[0]
                    defaults[group_attributes[name]] = value
            except AttributeError:
                # In some cases attrs is a list instead of a dict; skip these invalid groups
                continue

            try:
                groupname = defaults[groupname_field]
            except KeyError:
                logger.warning("Group is missing a required attribute '%s'" % groupname_field)
                continue

            kwargs = {
                groupname_field + '__iexact': groupname,
                'defaults': defaults,
            }

            try:
                group, created = Group.objects.get_or_create(**kwargs)
            except (IntegrityError, DataError) as e:
                logger.error("Error creating group %s: %s" % (groupname, e))
            else:
                if created:
                    logger.debug("Created group %s" % groupname)

        logger.info("Groups are synchronized")

    def ldap_search(self, filter, attributes, objecttype=None):
        """
        Query the configured LDAP server with the provided search filter and
        attribute list.
        """
        uri = get_setting('LDAP_SYNC_URI', strict=True)
        base_user = get_setting('LDAP_SYNC_BASE_USER', strict=True)
        base_pass = get_setting('LDAP_SYNC_BASE_PASS', strict=True)
        base = get_setting('LDAP_SYNC_BASE', strict=True)

        # ldap config
        service = Service(uri)

        # ldap authentication
        service.login(base_user, base_pass)

        # ldap search
        results = service.search(base, filter, attributes, objecttype)
        return results
