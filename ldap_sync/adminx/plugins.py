# coding=utf-8
import inspect
from django.contrib.auth import get_user_model
from django.template.loader import render_to_string
from django.utils.functional import cached_property
from django.utils.module_loading import import_string
from ldap_sync.models import LdapAccount
from ldap_sync.utils import get_setting
from xadmin.plugins.utils import get_context_dict
from xadmin.views.base import BaseAdminPlugin

User = get_user_model()


class LdapUserMigrationPlugin(BaseAdminPlugin):
	"""Plugin que cria um botão na tela de edição e envia o evento de migração de usuários
	"""

	def init_request(self, *args, **kwargs):
		model = getattr(self, 'model', None)
		return bool(inspect.isclass(model) and
		            issubclass(model, LdapAccount) and
		            len(args) > 0 and
		            self.user_queryset.exists())

	@cached_property
	def user_queryset(self):
		queryset = User.objects.filter(ldapobject__isnull=False)
		user_queryset_callbacks = get_setting('LDAP_SYNC_USER_QUERYSET_CALLBACKS', default=[])
		for callback in user_queryset_callbacks:
			callback = import_string(callback)
			queryset = callback(queryset)
		return queryset.filter(ldapobject__account__isnull=True)

	def block_nav_btns(self, context, nodes):
		context = get_context_dict(context)
		context['ldap_migration_url'] = self.get_admin_url("ldap_migration", self.admin_view.org_obj.pk)
		nodes.append(render_to_string("ldap_sync/user_migration.html", context=context))
