import logging
from django.conf import settings
from django.db import models
from django.utils.text import Truncator
from django.utils.translation import ugettext_lazy as _
from ldap_sync.fields.config import ConfigTextField

try:
    from ldap_sync.fields.encrypted import EncryptedCharField
except ImportError:
    # If the dependency doesn't exist use a default charfield
    EncryptedCharField = models.CharField


class LdapAccount(models.Model):
    """Model of LDAP account records"""
    username = models.CharField(verbose_name=_("User"), max_length=256)
    password = EncryptedCharField(verbose_name=_("Password"), max_length=350)
    uri = models.CharField(verbose_name="Server URI", max_length=350)
    options = ConfigTextField(verbose_name=_("Options"), blank=True,
                              sections=['sync', 'user_attributes',
                                        'user_attributes_defaults'])

    class Meta:
        verbose_name = "LDAP Account"
        verbose_name_plural = verbose_name + "s"

    def __str__(self):
        return "{0.uri}@{0.username}".format(self)


class LdapObject(models.Model):
    """Data information for a synchronized ldap object"""

    user = models.OneToOneField(settings.AUTH_USER_MODEL,
                                on_delete=models.CASCADE,
                                verbose_name=_("User"))
    account_name = models.CharField(_("Account name"),
                                    max_length=256)
    data = models.TextField(_("Data"), blank=True, null=True)

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return "{0.user}".format(self)

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

    def __str__(self):
        return "{0.status}/{0.total}".format(self)

    class Meta:
        verbose_name = _("Log")
        verbose_name_plural = _("Logs")


class LdapSyncLogMeta(models.Model):
    log = models.ForeignKey(LdapSyncLog,
                            on_delete=models.CASCADE)
    level = models.SmallIntegerField(_("Level"))
    text = models.TextField(_("Text"))

    def __str__(self):
        text = Truncator(self.text).chars(30, html=True)
        return "[{}] {}".format(logging.getLevelName(str(self.level)), text)

    class Meta:
        verbose_name = _("Log Info")
        verbose_name_plural = _("Log Infos")
