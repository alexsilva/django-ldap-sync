# coding=utf-8
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.http import JsonResponse
from ldap_sync.models import LdapAccount
from ldap_sync.utils import get_setting
from xadmin.views.base import BaseAdminView

User = get_user_model()


class LdapUserMigrationView(BaseAdminView):
	"""View que recebe o evento para migração dos usuários"""
	account_model = LdapAccount

	def post(self, request, account_id, **kwargs):
		if not self.has_model_perm(self.account_model, "change", self.user):
			raise PermissionDenied

		pk = self.account_model._meta.pk.to_python(account_id)
		account = self.account_model.objects.get(pk=pk)

		queryset = User.objects.all()
		user_queryset_callbacks = get_setting('LDAP_SYNC_USER_QUERYSET_CALLBACKS', default=[])
		for callback in user_queryset_callbacks:
			queryset = callback(queryset)

		queryset = queryset.filter(ldapobject__account__isnull=True)
		queryset.update(account=account)

		return JsonResponse({
			'total': queryset.count()
		})
