# coding=utf-8
import django.forms as django_forms


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
