# coding=utf-8
import copy
import hashlib
import json
import mimetypes
import traceback
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.exceptions import ImproperlyConfigured
from django.core.files.base import ContentFile
from django.core.management.base import BaseCommand
from django.db import DataError
from django.db import IntegrityError
from django.utils.encoding import force_bytes
from django.utils.module_loading import import_string
from io import StringIO
from ldap_sync.logger import Logger
from ldap_sync.models import LdapObject, LdapAccount
from ldap_sync.service import LdapSearch
from ldap_sync.utils import DEFAULT_ENCODING
from ldap_sync.utils import get_setting

try:
    import slugify
except ImportError:
    slugify = None


# django user model
User = get_user_model()

text_types = (str, bytes)

service_string = get_setting("LDAP_SYNC_SERVICE", default=LdapSearch)
if isinstance(service_string, text_types):
    LdapSearch = import_string(service_string)


class ContextLogger(object):
    def __call__(self, method, *args, **kwargs):
        # noinspection PyBroadException
        def wrapper(self_wrapper, *args_wrapper, **kwargs_wrapper):
            status = True
            try:
                return method(self_wrapper, *args_wrapper, **kwargs_wrapper)
            except Exception as exc:
                stream = StringIO()
                traceback.print_exc(file=stream)
                self_wrapper.logger.error(stream.getvalue())
                status = False
            finally:
                self_wrapper.logger.set_status(status)
        return wrapper


class UserSync(object):
    """
    Intermediate layer of synchronization
    """
    user_attrvalue_encoding = get_setting('LDAP_SYNC_USER_ATTRVALUE_ENCODING',
                                          default=DEFAULT_ENCODING)
    user_default_callback = get_setting('LDAP_SYNC_USER_DEFAULT_CALLBACK',
                                        default=None)
    removed_user_queryset_callbacks = get_setting('LDAP_SYNC_REMOVED_USER_QUERYSET_CALLBACKS',
                                                  default=[])
    username_callbacks = get_setting('LDAP_SYNC_USERNAME_CALLBACKS', default=[])
    username_field = (get_setting('LDAP_SYNC_USERNAME_FIELD') or getattr(User, 'USERNAME_FIELD', 'username'))
    user_callbacks = list(get_setting('LDAP_SYNC_USER_CALLBACKS', default=[]))
    removed_user_callbacks = list(get_setting('LDAP_SYNC_REMOVED_USER_CALLBACKS', default=[]))
    imagefield_filename_prefix = "ldap-image-"

    class InvalidImage(Exception):
        """An exception that occurs when the image is invalid"""
        pass

    def __init__(self, command, account, **options):
        """
        Initializing method
        :param command: Django command
        """
        self.command = command
        self.account = account
        self.pks = set()
        self.counter = 0

        self.options = options

        # config
        self.user_attributes = copy.deepcopy(options['user_attributes'])
        self.user_attributes_defaults = options.get("user_attributes_defaults", {})
        self.imagefield_default_ext = options.get('imagefield_default_ext')

        # validation
        self._validate_username_field()

        self.field_types = ('imagefield',)
        self.field_type_map = self._get_field_types()
        self.field_types_names = set(self.field_type_map.values())

        try:
            import magic
        except ImportError:
            self.logger.error(traceback.format_exc())
            magic = None

        self.magic = magic

    def _get_field_types(self):
        """Extracts the type of user field
        thumbnailPhoto=photo_ldap:imagefield
        thumbnailPhoto=photo_ldap
        """
        field_types = {}
        for key in self.user_attributes:
            value = self.user_attributes[key]
            try:
                value_name, field_type = value.split(":", 1)
            except ValueError:
                continue
            self.user_attributes[key] = value_name
            field_types[key] = field_types[value_name] = field_type
        return field_types

    def _validate_username_field(self):
        """Validations on the user field"""
        is_unique = User._meta.get_field(self.username_field).unique

        if not is_unique:
            raise ImproperlyConfigured("Field '%s' must be unique" % self.username_field)

        if self.username_field not in self.user_attributes.values():
            raise ImproperlyConfigured("'user_attributes' must contain the field '%s'" % self.username_field)

    def __getattr__(self, item):
        return getattr(self.command, item)

    def before(self):
        """Operations before running synchronization"""
        self.logger.set_synchronizing(True)

    def transform_imagefield(self, value):
        """Converts data from a binary image to BytesIO"""
        if isinstance(value, bytes):
            value = value.strip()
        if value:
            value = ContentFile(value)
        else:
            value = None
        return value

    @staticmethod
    def _file_hash(fp):
        block_size = 65536
        hasher = hashlib.sha1()
        buf = fp.read(block_size)
        while len(buf) > 0:
            hasher.update(buf)
            buf = fp.read(block_size)
        return hasher.hexdigest()

    def save_imagefield(self, user, field_values):
        """Assigns an image to the user"""

        def get_file_ext():
            """Try to get file extension"""
            if isinstance(content, ContentFile):
                buff = content.file.getvalue()
            else:
                buff = content

            mime = self.magic.from_buffer(buff, mime=True)

            # check if string/bytes
            assert isinstance(mime, text_types)

            type_name = mime.split("/", 1)[0]

            # Check if it's an image
            if not self.field_type_map[field_name].startswith(type_name):
                raise self.InvalidImage("mimetype '%s' is not an image" % mime)

            fext = mimetypes.guess_extension(mime)

            if isinstance(fext, text_types):
                fext = fext.strip()

            return fext or self.imagefield_default_ext

        username = getattr(user, self.username_field)

        for field_name in field_values:
            content = field_values[field_name]
            field = getattr(user, field_name)

            filename = self.imagefield_filename_prefix + hashlib.md5(force_bytes(user.pk)).hexdigest()

            if slugify is not None:
                filename = slugify.slugify(filename)

            # Add file extension
            if self.magic is not None and content is not None:
                try:
                    filename += get_file_ext()
                except self.InvalidImage as err:
                    self.logger.warning("Failed to get user ({0!s}) "
                                        "image ({1!s}) file extension".format(username, err))
                    continue
                except Exception as err:
                    self.logger.warning("Failed to get user ({0!s}) image (1!s) "
                                        "file extension".format(username, err))
                    continue
            else:
                filename += self.imagefield_default_ext
            valid_content = content is not None
            try:
                # check file changes
                with field.file as fp:
                    if not valid_content and field.field.null:
                        setattr(user, field_name, None)
                        changed = True
                    else:
                        changed = self._file_hash(fp) != self._file_hash(content)
            except Exception:
                changed = valid_content
            if valid_content:
                field.save(filename, content, False)
            return changed

    def _exclude_fields(self, attributes, names=()):
        """Exclude binary fields from attributes"""
        attributes = copy.deepcopy(attributes)
        excluded_fields = {}
        for field_name in self.field_type_map:
            if field_name in attributes and self.field_type_map[field_name] in names:
                excluded_fields[field_name] = attributes.pop(field_name)
        return attributes, excluded_fields

    def _ldapobject_update(self, user, attributes, **kwargs):
        """saves metadata from the synchronized user in the database"""
        attributes, _ = self._exclude_fields(attributes,
                                             names=self.field_types)
        qs = LdapObject.objects.filter(account=self.account,
                                       user=user)
        if not qs.exists():
            LdapObject.objects.create(
                account=self.account,
                user=user,
                account_name=kwargs['old_username'],
                data=json.dumps(attributes))
        elif kwargs['user_updated']:
            qs.update(
                account_name=kwargs['old_username'],
                data=json.dumps(attributes)
            )

    def execute(self, items):
        """ Synchronize a set of users """
        total = len(items)
        self.counter += total

        self.logger.info("Retrieved %d users" % total)
        self.logger.set_total(self.counter)

        for attributes in items:
            defaults = {}
            try:
                for name, value in attributes.items():
                    try:
                        field_type = self.field_type_map.get(self.user_attributes[name])
                        if field_type is not None:
                            value = getattr(self, "transform_" + field_type)(value)
                    except KeyError:
                        pass
                    if isinstance(value, bytes):
                        value = str(value, self.user_attrvalue_encoding)
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
                self.logger.warning("User is missing a required attribute '%s'" % self.username_field)
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
            if isinstance(self.user_default_callback, text_types):
                callback = import_string(self.user_default_callback)
                kwargs['defaults'].update(callback(**kwargs['defaults']))

            defaults, db_field_values = self._exclude_fields(defaults, names=self.field_types)
            user_updated = False
            try:
                user, created = User.objects.get_or_create(**kwargs)

                # pos save data
                for field_type in self.field_types_names:
                    method = getattr(self, "save_" + field_type)
                    if method(user, db_field_values):  # has field type changes
                        user_updated = True
            except (IntegrityError, DataError) as e:
                self.logger.error("Error creating user {0!s}/{1!s}: {2!s}".format(username, old_username, e))
            else:
                if created:
                    self.logger.debug("Created user {0!s}/{1!s}".format(username, old_username))
                    user.set_unusable_password()
                    user.save()
                    self._ldapobject_update(user, attributes,
                                            old_username=old_username,
                                            user_updated=True)
                else:
                    for name, ldap_value in defaults.items():
                        try:
                            user_value = getattr(user, name)
                        except AttributeError:
                            # This should not happen because it would indicate that the user models are different.
                            self.logger.debug("User {0!s} does not have attribute {1!s}".format(user, name))
                            continue
                        if user_value != ldap_value:
                            setattr(user, name, ldap_value)
                            user_updated = True

                    if user_updated:
                        self.logger.debug("Updated user {0!s}/{1!s}".format(username, old_username))

                    self._ldapobject_update(user, attributes,
                                            old_username=old_username,
                                            user_updated=user_updated)

                for path in self.user_callbacks:
                    callback = import_string(path)
                    user_updated = (callback(user, self.account, attributes,
                                            created=created, updated=user_updated) or
                                    user_updated)

                if user_updated:
                    user.save()

                if self.removed_user_callbacks:
                    self.pks.add(user.pk)

    def after(self):
        """Operations after performing synchronization"""
        try:
            self.check_removed()
        finally:
            self.logger.set_synchronizing(False)
            self.logger.info("Users are synchronized")

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
            queryset = User.objects.filter(ldapobject__account=self.account)

            if self.removed_user_queryset_callbacks:
                for path in self.removed_user_queryset_callbacks:
                    callback = import_string(path)
                    queryset = callback(queryset, self.account)

            # Consider only current user set, because of pagination
            django_pks = set(queryset.values_list("pk", flat=True))

            for user_pk in django_pks - self.pks:
                user = User.objects.get(pk=user_pk)
                for path in self.removed_user_callbacks:
                    callback = import_string(path)
                    callback(user, self.account)
                    self.logger.debug("Called %s for user %s" % (path, user))


class Command(BaseCommand):
    can_import_settings = True
    help = 'Synchronize users and groups from an authoritative LDAP server'
    ldap_account_model = LdapAccount
    logger = None

    def handle(self, *args, **options):
        for account in self.ldap_account_model.objects.all():
            self.logger = Logger(account)
            self.handle_user_sync(account)

    @ContextLogger()
    def handle_user_sync(self, account, **extra_options):
        config = account.options
        options = dict(
            user_filter=config.get('sync', 'user_filter', fallback=None),
            user_base_dn=config.get('sync', 'user_base_dn', fallback=None),
            user_attributes=dict(config.items('user_attributes')),
            user_attributes_defaults=dict(config.items('user_attributes_defaults')),
            imagefield_default_ext=config.get('sync', 'imagefield_default_ext',
                                              fallback=get_setting('LDAP_SYNC_IMAGEFIELD_DEFAULT_EXT',
                                                                   default=None)),
        )
        options['user_extra_attributes'] = (config.options('user_extra_attributes') if
                                            config.has_section('user_extra_attributes') else [])
        with UserSync(self, account, **options) as usersync:
            for users in self.search_users(account, **options):
                usersync.execute(users)
        return account

    def search_users(self, account, **options):
        """Retrieve user data from LDAP server."""
        user_filter = options.get('user_filter')
        if not user_filter:
            self.logger.debug('"user_filter" not configured, skipping user sync')
            return []

        user_base_dn = options.get('user_base_dn')
        if not user_base_dn:
            self.logger.debug('"user_base_dn" not configured, skipping user sync')
            return []

        user_attributes = options['user_attributes']
        user_extra_attributes = options.get('user_extra_attributes')

        attributes = set(user_attributes.keys())
        if user_extra_attributes:
            attributes.update(user_extra_attributes)

        search = self.get_connection(account)

        # query the configured LDAP server with the provided search filter and attribute list.
        return search.users(user_base_dn, user_filter, attributes)

    def get_connection(self, account) -> LdapSearch:
        """
        Connection object
        """
        # ldap config
        search = LdapSearch(account.uri)

        # ldap authentication
        search.login(account.username,
                     account.password)
        return search
