import json
import traceback
from StringIO import StringIO

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.exceptions import ImproperlyConfigured
from django.core.management.base import BaseCommand
from django.db import DataError
from django.db import IntegrityError
from django.utils.module_loading import import_string

from ldap_sync.logger import Logger
from ldap_sync.models import LdapObject
from ldap_sync.service import LdapSearch
from ldap_sync.utils import get_setting

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


class UserSync(object):
    """
    Intermediate layer of synchronization
    """
    user_attributes = get_setting('LDAP_SYNC_USER_ATTRIBUTES')
    user_attrvalue_encoding = get_setting('LDAP_SYNC_USER_ATTRVALUE_ENCODING',
                                          default='utf-8')
    user_attributes_defaults = get_setting('LDAP_SYNC_USER_ATTRIBUTES_DEFAULTS',
                                           default={})
    user_default_callback = get_setting('LDAP_SYNC_USER_DEFAULT_CALLBACK',
                                        default=None)
    removed_user_queryset_callbacks = get_setting('LDAP_SYNC_REMOVED_USER_QUERYSET_CALLBACKS',
                                                  default=[])
    username_callbacks = get_setting('LDAP_SYNC_USERNAME_CALLBACKS', default=[])
    username_field = get_setting('LDAP_SYNC_USERNAME_FIELD')
    if username_field is None:
        username_field = getattr(User, 'USERNAME_FIELD', 'username')
    user_callbacks = list(get_setting('LDAP_SYNC_USER_CALLBACKS', default=[]))
    removed_user_callbacks = list(get_setting('LDAP_SYNC_REMOVED_USER_CALLBACKS', default=[]))

    def __init__(self, command):
        """
        Initializing method
        :param command: Django command
        """
        self.command = command
        self.username_is_unique = User._meta.get_field(self.username_field).unique
        self.pks = set()
        self.counter = 0

    def __getattr__(self, item):
        return getattr(self.command, item)

    def before(self):
        """Operations before running synchronization"""
        self.logger.set_synchronizing(True)

    @staticmethod
    def _ldapobject_save(user, old_username, attributes):
        # Saves the data in json of the object.
        ldap_object, created = LdapObject.objects.get_or_create(user=user)
        ldap_object.account_name = old_username
        ldap_object.data = json.dumps(attributes)
        ldap_object.save()

    def execute(self, items):
        """ Synchronize a set of users """
        if not self.username_is_unique:
            raise ImproperlyConfigured(u"Field '%s' must be unique" % self.username_field)

        if self.username_field not in self.user_attributes.values():
            error_msg = (u"LDAP_SYNC_USER_ATTRIBUTES must contain the field '%s'" % self.username_field)
            raise ImproperlyConfigured(error_msg)

        total = len(items)
        self.counter += total

        self.logger.info(u"Retrieved %d users" % total)
        self.logger.set_total(self.counter)

        for attributes in items:
            defaults = {}
            try:
                for name, value in attributes.items():
                    if isinstance(value, str):
                        value = unicode(value, self.user_attrvalue_encoding)
                    try:
                        # If the value of the attribute does not exist, it uses the default.
                        if not value:
                            value = self.user_attributes_defaults.get(name)
                        defaults[self.user_attributes[name]] = value
                    except KeyError:
                        pass
            except AttributeError:
                # In some cases attributes is a list instead of a dict; skip these invalid users
                continue

            try:
                username = defaults[self.username_field]
            except KeyError:
                self.logger.warning(u"User is missing a required attribute '%s'" % self.username_field)
                continue

            old_username = username

            # username changes
            for path in self.username_callbacks:
                callback = import_string(path)
                username = callback(username)
                defaults[self.username_field] = username

            kwargs = {
                self.username_field + '__exact': username,
                'defaults': defaults,
            }
            if isinstance(self.user_default_callback, (str, unicode)):
                callback = import_string(self.user_default_callback)
                kwargs['defaults'] = callback(**kwargs['defaults'])

            try:
                user, created = User.objects.get_or_create(**kwargs)
            except (IntegrityError, DataError) as e:
                self.logger.error(u"Error creating user {0!s}/{1!s}: {2!s}".format(username, old_username, e))
            else:
                self._ldapobject_save(user, old_username, attributes)
                updated = False
                if created:
                    self.logger.debug(u"Created user {0!s}/{1!s}".format(username, old_username))
                    user.set_unusable_password()
                else:
                    for name, ldap_value in defaults.items():
                        try:
                            user_value = getattr(user, name)
                        except AttributeError:
                            # This should not happen because it would indicate that the user models are different.
                            self.logger.debug(u"User {0!s} does not have attribute {1!s}".format(user, name))
                            continue
                        if user_value != ldap_value:
                            setattr(user, name, ldap_value)
                            updated = True
                    if updated:
                        self.logger.debug(u"Updated user {0!s}/{1!s}".format(username, old_username))

                for path in self.user_callbacks:
                    callback = import_string(path)
                    callback(user, attributes, created, updated)

                user.save()

                if self.removed_user_callbacks:
                    self.pks.add(user.pk)

    def after(self):
        """Operations after performing synchronization"""
        try:
            self.check_removed()
        finally:
            self.logger.set_synchronizing(False)
            self.logger.info(u"Users are synchronized")

    def __enter__(self):
        self.before()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None and exc_val is None and exc_tb is None:
            self.after()
        else:
            self.logger.set_synchronizing(False)

    def check_removed(self):
        """Makes user removal not found on ldap db"""
        if self.removed_user_callbacks:
            queryset = User.objects.all()

            if self.removed_user_queryset_callbacks:
                for path in self.removed_user_queryset_callbacks:
                    callback = import_string(path)
                    queryset = callback(queryset)

            # Consider only current user set, because of pagination
            django_pks = set(queryset.values_list("pk", flat=True))

            for user_pk in django_pks - self.pks:
                user = User.objects.get(pk=user_pk)
                for path in self.removed_user_callbacks:
                    callback = import_string(path)
                    callback(user)
                    self.logger.debug(u"Called %s for user %s" % (path, user))


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
            self.search_groups(ldap_groups)

        with UserSync(self) as usync:
            for users in self.search_users():
                usync.execute(users)

    def search_users(self):
        """Retrieve user data from LDAP server."""
        user_filter = get_setting('LDAP_SYNC_USER_FILTER')
        if not user_filter:
            self.logger.debug(u'LDAP_SYNC_USER_FILTER not configured, skipping user sync')
            return []

        user_attributes = get_setting('LDAP_SYNC_USER_ATTRIBUTES', strict=True)
        user_keys = set(user_attributes.keys())
        user_extra_attributes = get_setting('LDAP_SYNC_USER_EXTRA_ATTRIBUTES', default=[])
        user_keys.update(user_extra_attributes)

        return self.ldap_search("users", user_filter, user_keys)

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

    def search_groups(self, ldap_groups):
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
