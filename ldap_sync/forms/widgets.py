# coding=utf-8
from django.contrib.auth.forms import ReadOnlyPasswordHashWidget
from ldap_sync.fields.encrypted import EncryptedCharField


class LdapReadOnlyPasswordHashWidget(ReadOnlyPasswordHashWidget):
	template_name = "ldap_sync/forms/read_only_password_hash.html"

	def get_context(self, name, value, attrs, **kwargs):
		"""Convert password from text to hash"""
		field = EncryptedCharField()
		value = field.to_python(value)
		return super().get_context(name, value, attrs, **kwargs)
