# coding=utf-8
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from ldap_sync.forms.widgets import LdapReadOnlyPasswordHashWidget


class LdapReadOnlyPasswordHashField(ReadOnlyPasswordHashField):
	widget = LdapReadOnlyPasswordHashWidget
