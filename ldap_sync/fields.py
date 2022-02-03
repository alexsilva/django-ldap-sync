# coding=utf-8
import base64
from cryptography.fernet import Fernet
from django.conf import settings
from django.db import models
from django.utils.encoding import force_bytes, force_str


class EncryptedData(str):
	"""Encrypted data string"""
	pass


class EncryptedCharField(models.CharField):
	"""CharField with encrypted data"""

	def __init__(self, key=None, *args, **kwargs):
		super().__init__(*args, **kwargs)
		# Encryption key.
		self.key = self.generate_key(key)
		self.fernet = Fernet(self.key)

	@staticmethod
	def generate_key(key):
		key = key or settings.SECRET_KEY
		key = force_bytes(key[0:32])
		return base64.urlsafe_b64encode(key)

	def encrypt(self, data):
		data = force_bytes(data)
		data = self.fernet.encrypt(data)
		return EncryptedData(data, 'ascii')

	def decrypt(self, token):
		return self.fernet.decrypt(token.encode('ascii'))

	def from_db_value(self, value, expression, connection):
		"""Decrypt data from the database"""
		if value is None:
			return value
		value = self.decrypt(value)
		value = force_str(value)
		return value

	def to_python(self, value):
		"""Encrypt database data"""
		if isinstance(value, EncryptedData):
			return value
		if value is None:
			return value
		value = self.encrypt(value)
		return value

	def deconstruct(self):
		name, path, args, kwargs = super().deconstruct()
		if self.key is not None:
			kwargs['key'] = self.key
		return name, path, args, kwargs
