import logging
from StringIO import StringIO

from django.core.exceptions import ImproperlyConfigured
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db import DataError
from django.db import IntegrityError
from django.utils.module_loading import import_string
from ldap_sync.service import LdapSearch
from ldap_sync.utils import get_setting
from ldap_sync.logger import Logger
from ldap_sync.models import LdapObject
import traceback

# django user model
User = get_user_model()

service_string = get_setting("LDAP_SYNC_SERVICE", default=LdapSearch)
if isinstance(service_string, (str, unicode)):
    LdapSearch = import_string(service_string)


class ContextLogger(object):
    def __call__(self, method, *args, **kwargs):
        def wrapper(this, *_args, **_kwargs):
            try:
                method_result = method(this, *_args, **_kwargs)
            except:
                stream = StringIO()
                traceback.print_exc(file=stream)
                this.logger.error(stream.getvalue())
                raise
            this.logger.set_status(True)
            return method_result
        return wrapper


class Command(BaseCommand):
    can_import_settings = True
    help = 'Synchronize users and groups from an authoritative LDAP server'

    def __init__(self, *args, **kwargs):
        super(Command, self).__init__(*args, **kwargs)
        self.logger = Logger()

    @ContextLogger()
    def handle(self, *args, **options):
        ldap_groups = self.get_ldap_groups()
        if ldap_groups:
            self.sync_ldap_groups(ldap_groups)

        # the results come paginated.
        user_counter = 0
        self.logger.set_synchronizing(True)
        try:
            for ldap_users in self.get_ldap_users():
                total = len(ldap_users)
                user_counter += total
                self.logger.set_total(user_counter)
                self.logger.info("Retrieved %d users" % total)
                self.sync_ldap_users(ldap_users)
        finally:
            self.logger.set_synchronizing(False)
        self.logger.info("Users are synchronized")

    def get_ldap_users(self):
        """Retrieve user data from LDAP server."""
        user_filter = get_setting('LDAP_SYNC_USER_FILTER')
        if not user_filter:
            self.logger.debug('LDAP_SYNC_USER_FILTER not configured, skipping user sync')
            yield []

        user_attributes = get_setting('LDAP_SYNC_USER_ATTRIBUTES', strict=True)
        user_keys = set(user_attributes.keys())
        user_extra_attributes = get_setting('LDAP_SYNC_USER_EXTRA_ATTRIBUTES', default=[])
        user_keys.update(user_extra_attributes)

        for ldap_users in self.ldap_search("users", user_filter, user_keys):
            yield ldap_users

    @staticmethod
    def ldap_user_save(user, old_username, user_data):
        # Saves the data in json of the object.
        ldap_object, created = LdapObject.objects.get_or_create(user=user)
        ldap_object.account_name = old_username
        ldap_object.data = user_data['json']
        ldap_object.save()

    def sync_ldap_users(self, ldap_users):
        """Synchronize users with local user model."""
        user_attributes = get_setting('LDAP_SYNC_USER_ATTRIBUTES')
        user_attributes_defaults = get_setting('LDAP_SYNC_USER_ATTRIBUTES_DEFAULTS',
                                               default={})
        removed_user_queryset_callbacks = get_setting('LDAP_SYNC_REMOVED_USER_QUERYSET_CALLBACKS',
                                                      default=[])
        username_callbacks = get_setting('LDAP_SYNC_USERNAME_CALLBACKS', default=[])
        username_field = get_setting('LDAP_SYNC_USERNAME_FIELD')
        if username_field is None:
            username_field = getattr(User, 'USERNAME_FIELD', 'username')
        user_callbacks = list(get_setting('LDAP_SYNC_USER_CALLBACKS', default=[]))
        removed_user_callbacks = list(get_setting('LDAP_SYNC_REMOVED_USER_CALLBACKS', default=[]))
        ldap_usernames = set()

        if not User._meta.get_field(username_field).unique:
            raise ImproperlyConfigured("Field '%s' must be unique" % username_field)

        if username_field not in user_attributes.values():
            error_msg = ("LDAP_SYNC_USER_ATTRIBUTES must contain the field '%s'" % username_field)
            raise ImproperlyConfigured(error_msg)

        for user_data in ldap_users:
            attributes = user_data['attributes']
            defaults = {}
            try:
                for name, value in attributes.items():
                    try:
                        if isinstance(value, str):
                            value = value.decode('utf-8')
                        # If the value of the attribute does not exist, it uses the default.
                        if not value:
                            value = user_attributes_defaults.get(name)
                        defaults[user_attributes[name]] = value
                    except KeyError:
                        pass
            except AttributeError:
                # In some cases attributes is a list instead of a dict; skip these invalid users
                continue

            try:
                username = defaults[username_field]
            except KeyError:
                self.logger.warning("User is missing a required attribute '%s'" % username_field)
                continue

            old_username = username

            # username changes
            for path in username_callbacks:
                callback = import_string(path)
                username = callback(username)
                defaults[username_field] = username

            kwargs = {
                username_field + '__exact': username,
                'defaults': defaults,
            }

            try:
                user, created = User.objects.get_or_create(**kwargs)
            except (IntegrityError, DataError) as e:
                self.logger.error("Error creating user {0!s}/{1!s}: {2!s}".format(username, old_username, e))
            else:
                self.ldap_user_save(user, old_username, user_data)
                updated = False
                if created:
                    self.logger.debug("Created user {0!s}/{1!s}".format(username, old_username))
                    user.set_unusable_password()
                else:
                    for name, attr in defaults.items():
                        current_attr = getattr(user, name, None)
                        if current_attr != attr:
                            setattr(user, name, attr)
                            updated = True
                    if updated:
                        self.logger.debug("Updated user {0!s}/{1!s}".format(username, old_username))

                for path in user_callbacks:
                    callback = import_string(path)
                    callback(user, attributes, created, updated)

                user.save()

                if removed_user_callbacks:
                    ldap_usernames.add(username)

        if removed_user_callbacks:
            queryset = User.objects.all()
            if removed_user_queryset_callbacks:
                for path in removed_user_queryset_callbacks:
                    callback = import_string(path)
                    queryset = callback(queryset)
            users = queryset.values_list(username_field, flat=True)
            django_usernames = set(users)
            for username in django_usernames - ldap_usernames:
                user = User.objects.get(**{username_field: username})
                for path in removed_user_callbacks:
                    callback = import_string(path)
                    callback(user)
                    self.logger.debug("Called %s for user %s" % (path, user))

    def get_ldap_groups(self):
        """Retrieve groups from LDAP server."""
        group_filter = get_setting('LDAP_SYNC_GROUP_FILTER')
        if not group_filter:
            self.logger.debug('LDAP_SYNC_GROUP_FILTER not configured, skipping group sync')
            return []

        group_attributes = get_setting('LDAP_SYNC_GROUP_ATTRIBUTES', strict=True)

        groups = self.ldap_search("groups", group_filter, group_attributes.keys())
        self.logger.debug("Retrieved %d groups" % len(groups))
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
                    if isinstance(attribute[0], str):
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
                self.logger.warning("Group is missing a required attribute '%s'" % groupname_field)
                continue

            kwargs = {
                groupname_field + '__iexact': groupname,
                'defaults': defaults,
            }

            try:
                group, created = Group.objects.get_or_create(**kwargs)
            except (IntegrityError, DataError) as e:
                self.logger.error("Error creating group %s: %s" % (groupname, e))
            else:
                if created:
                    self.logger.debug("Created group %s" % groupname)

        self.logger.info("Groups are synchronized")

    def ldap_search(self, sname, sfilter, attributes):
        """
        Query the configured LDAP server with the provided search filter and
        attribute list.
        """
        uri = get_setting('LDAP_SYNC_URI', strict=True)
        username = get_setting('LDAP_SYNC_BASE_USER', strict=True)
        password = get_setting('LDAP_SYNC_BASE_PASS', strict=True)
        base_dn = get_setting('LDAP_SYNC_BASE', strict=True)

        # ldap config
        ldap_search = LdapSearch(uri)

        # ldap authentication
        ldap_search.login(username, password)

        # ldap search
        return getattr(ldap_search, sname)(base_dn, sfilter, attributes)
