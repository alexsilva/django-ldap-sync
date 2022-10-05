# coding=utf-8
from django.utils.translation import ugettext_lazy as _
from django.apps import AppConfig


class LdapSyncConfig(AppConfig):
    name = 'ldap_sync'
    verbose_name = _("Ldap sync")
