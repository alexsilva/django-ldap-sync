# coding=utf-8
import configparser
import io
from django.core.exceptions import ValidationError
from django.db import models


class ConfigParserText(configparser.ConfigParser):
	"""Show config as text"""
	optionxform = str

	def to_text(self):
		stream = io.StringIO()
		self.write(stream)
		return stream.getvalue()

	def __str__(self):
		return self.to_text()


class ConfigTextField(models.TextField):
	"""Converts text settings to configuration object
	"""

	def __init__(self, sections=None, *args, **kwargs):
		super().__init__(*args, **kwargs)
		# sections required
		self.sections = sections

	def deconstruct(self):
		name, path, args, kwargs = super().deconstruct()
		if self.sections is not None:
			kwargs['sections'] = self.sections
		return name, path, args, kwargs

	def value_to_string(self, obj):
		"""Converting field data for serialization"""
		value = self.value_from_object(obj)
		return self.get_prep_value(value)

	@staticmethod
	def get_config_parser():
		return ConfigParserText(allow_no_value=True)

	def from_db_value(self, value, expression, connection):
		if value is None:
			return value
		config = self.get_config_parser()
		config.read_string(value)
		return config

	def get_prep_value(self, value):
		if value is None:
			return value
		elif isinstance(value, str):
			return value

		stream = io.StringIO()
		value.write(stream)

		return stream.getvalue()

	def to_python(self, value):
		if value is None:
			return value
		elif isinstance(value, configparser.ConfigParser):
			return value
		config = self.get_config_parser()
		try:
			config.read_string(value)
		except configparser.ParsingError as exc:
			raise ValidationError(exc)
		if self.sections is not None:
			sections = config.sections()
			if [s for s in self.sections if s in sections] != self.sections:
				raise ValidationError("missing sections %(sections)s" % {'sections': self.sections})
		return config
