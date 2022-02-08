# coding=utf-8
import django.db.models as django_models
import django.forms as django_forms
import logging
from django.contrib.auth import get_user_model
from django.utils.translation import ugettext_lazy as _
from ldap_sync.adminx.forms import LdapAccountForm
from ldap_sync.adminx.plugins import LdapUserMigrationPlugin
from ldap_sync.adminx.views import LdapUserMigrationView
from ldap_sync.fields.encrypted import EncryptedCharField
from ldap_sync.models import LdapAccount
from ldap_sync.models import LdapSyncLog, LdapSyncLogMeta, LdapObject
from xadmin import site, sites
from xadmin.views import ModelFormAdminView

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
	form = LdapAccountForm
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
	formfield_overrides = {
		EncryptedCharField: {
			'widget': django_forms.PasswordInput(render_value=True),
			'strip': False
		},
		django_models.TextField: {
			'widget': django_forms.Textarea(attrs={'rows': 25}),
		}
	}


site.register_plugin(LdapUserMigrationPlugin, ModelFormAdminView)
site.register_view(r"^ldap-migration/(\d+)", LdapUserMigrationView, "ldap_migration")

site.register(LdapObject, LdapObjectAdmin)
site.register(LdapSyncLog, LdapSearchAdmin)
