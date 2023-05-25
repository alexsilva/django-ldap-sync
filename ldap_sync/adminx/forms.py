# coding=utf-8
import django.forms as django_forms
from django.utils.translation import gettext_lazy as _
from fernet_fieldhasher.forms.fields import ReadOnlyPasswordHashField


class LdapAccountForm(django_forms.ModelForm):

	def clean_username(self):
		"""Valida o formato e a inclusão do domínio ms"""
		username = self.cleaned_data['username']
		try:
			domain, _ = username.split("\\")
		except ValueError:
			raise django_forms.ValidationError("Formato para o nome de usuário inválido. Esperado 'domínio\\usuário'.")
		if not domain:
			raise django_forms.ValidationError("Necessário a inclusão do domínio ao nome de usuário.")
		if not _:
			raise django_forms.ValidationError("Forneça um nome de usuário válido.")
		return username


class LdapAccountChangeForm(LdapAccountForm):
	password = ReadOnlyPasswordHashField(label=_("Password"))

	def clean_password(self):
		# Regardless of what the user provides, return the initial value.
		# This is done here, rather than on the field, because the
		# field does not have access to the initial value
		return self.initial.get('password')
