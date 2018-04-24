from django.db import models
from django.conf import settings
from django.utils.translation import ugettext_lazy as _
import logging

from django.utils.text import Truncator


class LdapObject(models.Model):
    """Data information for a synchronized ldap object"""

    user = models.OneToOneField(settings.AUTH_USER_MODEL,
                                verbose_name=_("User"))
    account_name = models.CharField(_("Account name"),
                                    max_length=256)
    data = models.TextField(_("Data"), blank=True, null=True)

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    def __unicode__(self):
        return u"{0.user}".format(self)

    class Meta:
        verbose_name = _("Ldap User")
        verbose_name_plural = _("Ldap Users")


class LdapSyncLog(models.Model):
    """Synchronization process logs"""

    created = models.DateTimeField(_("Sync date"), auto_now_add=True)
    status = models.BooleanField(_("Status"), default=False)
    synchronizing = models.BooleanField(_("Synchronizing"), default=False)

    # Total of synchronized objects
    total = models.IntegerField(_("Total"), default=0)

    def __unicode__(self):
        return u"{0.status}/{0.total}".format(self)

    class Meta:
        verbose_name = _("Log")
        verbose_name_plural = _("Logs")


class LdapSyncLogMeta(models.Model):
    log = models.ForeignKey(LdapSyncLog)
    level = models.SmallIntegerField(_("Level"))
    text = models.TextField(_("Text"))

    def __unicode__(self):
        text = Truncator(self.text).chars(30, html=True)
        return u"[{}] {}".format(logging.getLevelName(self.level), text)

    class Meta:
        verbose_name = _("Log Info")
        verbose_name_plural = _("Log Infos")
