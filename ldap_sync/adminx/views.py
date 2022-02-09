# coding=utf-8
from django.utils.translation import ugettext_lazy as _
import django.forms as django_forms
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.http import JsonResponse
from django.template.loader import render_to_string
from django.utils.encoding import force_str
from django.utils.module_loading import import_string
from ldap_sync.fields.encrypted import EncryptedCharField
from ldap_sync.models import LdapAccount
from ldap_sync.utils import get_setting
from xadmin.views import UpdateAdminView
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

		queryset = User.objects.filter(ldapobject__isnull=False)
		user_queryset_callbacks = get_setting('LDAP_SYNC_USER_QUERYSET_CALLBACKS', default=[])
		for callback in user_queryset_callbacks:
			callback = import_string(callback)
			queryset = callback(queryset)

		queryset = queryset.filter(ldapobject__account__isnull=True)
		for user in queryset:
			user.ldapobject_set.update(account=account)

		return JsonResponse({
			'total': queryset.count()
		})


class LdapChangePasswordView(UpdateAdminView):
	model = LdapAccount
	fields = ('password',)
	formfield_overrides = {
		EncryptedCharField: {
			'widget': django_forms.PasswordInput,
			'initial': None
		}
	}

	def get_context(self):
		context = super().get_context()
		context.update(
			show_delete_link=False,
			show_save_as_new=False,
			show_save_and_add_another=False,
			show_save_and_continue=False
		)
		return context

	def block_submit_more_btns(self, context, nodes):
		nodes.append(render_to_string("ldap_sync/adminx/submit_line.html", context={
			'model_edit_url': self.get_model_url(self.model, "change", self.org_obj.pk)
		}))

	def post_response(self):
		response = super().post_response()
		# Returns to the model editing screen.
		if isinstance(response, str):
			self.message_user(_("Field %(fields)s successfully changed") % {
				'fields': ",".join([force_str(self.opts.get_field(field_name).verbose_name).lower()
				                    for field_name in self.fields])
			})
			response = self.get_model_url(self.model, "change", self.org_obj.pk)
		return response
