import logging
from django.utils.translation import ugettext_lazy as _
from xadmin import site
from .models import LdapSyncLog, LdapSyncLogMeta


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
    inlines = (LdapSearchInline,)
    readonly_fields = ["status", "total"]
    list_display = (
        "created",
        "total",
        "status"
    )

site.register(LdapSyncLog, LdapSearchAdmin)
