import logging
from django.utils.translation import ugettext_lazy as _
from xadmin import site
from .models import LdapSyncLog, LdapSyncLogMeta, LdapObject


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
    list_display = (
        "user",
        "account_name"
    )


site.register(LdapObject, LdapObjectAdmin)
site.register(LdapSyncLog, LdapSearchAdmin)
