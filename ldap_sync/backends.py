# coding=utf-8
from django.utils.functional import cached_property
from django.utils.module_loading import import_string

from ldap_sync.service import LdapSearch, LdapSearchException
from ldap_sync.utils import get_setting

__all__ = ['LdapBackend']


class LdapBackend:
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

	def authenticate(self, request, username=None, password=None):
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
