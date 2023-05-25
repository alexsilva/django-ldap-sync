# coding=utf-8
import logging
import io
import django.forms as django_forms
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.http import JsonResponse
from django.template.loader import render_to_string
from django.utils.encoding import force_str
from django.utils.translation import ugettext_lazy as _
from xadmin.views import UpdateAdminView
from xadmin.views.base import BaseAdminView
from django.core.management import call_command
from fernet_fieldhasher.fields import FernetPasswordHashField
from ldap_sync.models import LdapAccount

User = get_user_model()

logger = logging.getLogger("ldapsync")


class LdapUserMigrationView(BaseAdminView):
	"""View que recebe o evento para migração dos usuários"""
	model = LdapAccount
	opts = model._meta

	def post(self, request, account_id, **kwargs):
		if not self.has_model_perm(self.model, "change", self.user):
			raise PermissionDenied
		stdout = io.StringIO()
		# noinspection PyBroadException
		try:
			account_id = self.opts.pk.to_python(account_id)
			logger.info("starting user migration to account: %d" % account_id)
			count = int(call_command("syncldap_migrate", account_id=account_id, stdout=stdout))
			logger.info(stdout.getvalue().strip('\n '))
			logger.info("migrated %d users" % count)
		except Exception as exc:
			logger.exception("migrate user account: %s" % account_id)
			logger.info(stdout.getvalue())
			count = 0
		return JsonResponse({
			'total': count
		})


class LdapChangePasswordView(UpdateAdminView):
	model = LdapAccount
	fields = ('password',)
	formfield_overrides = {
		FernetPasswordHashField: {
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
