# coding=utf-8
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.utils.functional import cached_property
from django.utils.module_loading import import_string

from ldap_sync.service import LdapSearch, LdapSearchException
from ldap_sync.utils import get_setting

User = get_user_model()


__all__ = ['LdapBackend']


class LdapBackend(ModelBackend):
	"""
	Backend that assists in authentication with ldap.
	"""

	@cached_property
	def service(self):
		search = get_setting("LDAP_SYNC_SERVICE", default=LdapSearch)
		if isinstance(search, str):
			search = import_string(search)
		return search

	def _get_login_user(self, search, request,
	                    username=None,
	                    password=None):
		"""User after bind check"""
		raise NotImplementedError

	def get_username_field(self):
		"""Campo do nome de usuário configurado para o ldap (active directory)"""
		username_field = (get_setting('LDAP_SYNC_USERNAME_FIELD') or
		                  User.USERNAME_FIELD)
		return username_field

	def authenticate(self, request, username=None, password=None, **kwargs):
		if username is None:
			username = kwargs.get(self.get_username_field())
			if username is None:
				return None
		auth = get_setting('LDAP_SYNC_BASE_USER')
		uri = get_setting('LDAP_SYNC_URI')

		domain, user = auth.split('\\')

		auth_username = '\\'.join([domain, username])

		search = self.service(uri)

		try:
			search.login(auth_username, password)
		except LdapSearchException:
			pass
		else:
			return self._get_login_user(search, request, username, password)
