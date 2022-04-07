# coding=utf-8
from django.contrib.auth import get_user_model
from django.core.management import BaseCommand
from django.utils.module_loading import import_string

from ldap_sync.models import LdapAccount
from ldap_sync.utils import get_setting

User = get_user_model()


class Command(BaseCommand):
	help = """
	migrate existing user to an account
	"""
	account_model = LdapAccount
	account_opts = account_model._meta

	def add_arguments(self, parser):
		parser.add_argument('--account-id', type=int, help="Account id",
		                    required=True)

	def handle(self, *args, **options):
		account_id = options['account_id']

		pk = self.account_opts.pk.to_python(account_id)
		account = self.account_model.objects.get(pk=pk)

		queryset = User.objects.filter(ldapobject__isnull=False)
		user_queryset_callbacks = get_setting('LDAP_SYNC_USER_QUERYSET_CALLBACKS', default=[])
		for callback in user_queryset_callbacks:
			callback = import_string(callback)
			queryset = callback(queryset)

		queryset = queryset.filter(ldapobject__account__isnull=True)
		for user in queryset:
			user.ldapobject_set.update(account=account)
		return str(queryset.count())
