# coding=utf-8
from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class LdapSyncConfig(AppConfig):
	name = 'ldap_sync'
	verbose_name = _("Ldap sync")

	def ready(self):
		from ldap_sync.signal_register import ready

		ready(self)
