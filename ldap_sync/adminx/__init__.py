# coding=utf-8
import django.db.models as django_models
import django.forms as django_forms
import logging
from django.contrib.auth import get_user_model
from django.utils.translation import ugettext_lazy as _
from ldap_sync.adminx.forms import LdapAccountForm, LdapAccountChangeForm
from ldap_sync.adminx.plugins import LdapUserMigrationPlugin, LdapPasswordChangePlugin
from ldap_sync.adminx.views import LdapUserMigrationView, LdapChangePasswordView
from ldap_sync.models import LdapAccount
from ldap_sync.models import LdapSyncLog, LdapSyncLogMeta, LdapObject
from xadmin import site, sites
from xadmin.views import ModelFormAdminView, UpdateAdminView, CreateAdminView, DetailAdminView

User = get_user_model()


class LdapSearchInline(object):
	model = LdapSyncLogMeta
	exclude = ("level",)
	readonly_fields = ['level_text_show', 'text']
	can_delete = False
	style = "table"
	extra = 0

	def level_text_show(self, obj):
		return logging.getLevelName(obj.level)

	level_text_show.short_description = _("Level")
	level_text_show.allow_tags = True
	level_text_show.is_column = True


class LdapSearchAdmin(object):
	""""""
	refresh_times = range(15, 61, 15)

	inlines = (LdapSearchInline,)
	readonly_fields = ["synchronizing", "total", "status"]
	list_filter = (
		"synchronizing",
		"created",
		"status"
	)
	list_display = (
		"created",
		"synchronizing",
		"total",
		"status"
	)


class LdapObjectAdmin(object):
	""""""
	search_fields = (
		"user__username",
		"user__first_name",
		"user__last_name",
	)
	list_display = (
		"user",
		"account_name",
		"account",
		'is_active'
	)


@sites.register(LdapAccount)
class LdapAccountAdmin(object):
	password_change_fields = ('password',)
	form_detail_fields = (
		'username',
		'uri',
		'domain',
		'order',
		'options'
	)
	fields = (
		'username',
		'password',
		'uri',
		'domain',
		'order',
		'options'
	)

	list_display = (
		'__str__',
		'order'
	)

	def get_model_form(self, **kwargs):
		if isinstance(self, CreateAdminView):
			self.form = LdapAccountForm
		elif isinstance(self, UpdateAdminView) and self.org_obj:
			self.form = LdapAccountChangeForm
		elif isinstance(self, DetailAdminView):
			kwargs['fields'] = self.form_detail_fields
		return super().get_model_form(**kwargs)

	formfield_overrides = {
		django_models.TextField: {
			'widget': django_forms.Textarea(attrs={'rows': 25}),
		}
	}


site.register_view(r"^ldap-migration/(\d+)", LdapUserMigrationView, "ldap_migration")
site.register_view(r"^ldap-password/(\d+)/update", LdapChangePasswordView, "ldap_password_change")

site.register_plugin(LdapUserMigrationPlugin, ModelFormAdminView)
site.register_plugin(LdapPasswordChangePlugin, UpdateAdminView)

site.register(LdapObject, LdapObjectAdmin)
site.register(LdapSyncLog, LdapSearchAdmin)
