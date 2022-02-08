# coding=utf-8
import inspect
from django.contrib.auth import get_user_model
from django.template.loader import render_to_string
from ldap_sync.models import LdapAccount
from xadmin.plugins.utils import get_context_dict
from xadmin.views.base import BaseAdminPlugin

User = get_user_model()


class LdapUserMigrationPlugin(BaseAdminPlugin):
	"""Plugin que cria um botão na tela de edição e envia o evento de migração de usuários
	"""

	def init_request(self, *args, **kwargs):
		model = getattr(self, 'model', None)
		return inspect.isclass(model) and issubclass(model, LdapAccount) and len(args) > 0

	def block_nav_btns(self, context, nodes):
		context = get_context_dict(context)
		context['ldap_migration_url'] = self.get_admin_url("ldap_migration", self.admin_view.org_obj.pk)
		nodes.append(render_to_string("ldap_sync/user_migration.html", context=context))
