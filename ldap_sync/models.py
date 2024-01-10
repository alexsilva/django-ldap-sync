# coding=utf-8
import logging
from django.conf import settings
from django.db import models
from django.utils.formats import date_format
from django.utils.text import Truncator
from django.utils.translation import gettext_lazy as _
from ldap_sync.fields.config import ConfigTextField
from ldap_sync.fields.encrypted import EncryptedHashField


class LdapAccount(models.Model):
    """Model of LDAP account records"""
    username = models.CharField(verbose_name=_("User"), max_length=256,
                                help_text=_("domain inclusion required 'domain\\username'"))
    password = EncryptedHashField(verbose_name=_("Password"), text_length=350)
    uri = models.CharField(verbose_name=_("Server URI"), max_length=350)
    domain = models.CharField(verbose_name=_("User domain"),
                              max_length=128,
                              null=True)
    options = ConfigTextField(verbose_name=_("Options"), blank=True,
                              sections=['sync', 'user_attributes',
                                        'user_attributes_defaults'])
    order = models.IntegerField(verbose_name=_("Order"), default=0)

    class Meta:
        verbose_name = _("LDAP Account")
        verbose_name_plural = _("LDAP Accounts")
        ordering = ("order",)

    def __str__(self):
        return "{0.uri}@{0.username}".format(self)


class LdapObject(models.Model):
    """Data information for a synchronized ldap object"""
    user = models.ForeignKey(settings.AUTH_USER_MODEL,
                             on_delete=models.CASCADE,
                             verbose_name=_("User"))
    account = models.ForeignKey(LdapAccount, verbose_name=_("LDAP Account"),
                                on_delete=models.CASCADE,
                                null=True)
    is_active = models.BooleanField(verbose_name=_("Is active"),
                                    default=True)
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


class LdapObjectLog(models.Model):
    """Log model of changes made to the object"""
    ldap_object = models.ForeignKey(LdapObject, verbose_name=_("Ldap User"),
                                    on_delete=models.CASCADE)
    message = models.CharField(verbose_name=_("Message"), max_length=512)
    created = models.DateTimeField(verbose_name=_("Created at"), auto_now_add=True)

    def __str__(self):
        return f'{self.message}'

    class Meta:
        verbose_name = _("Object change")
        verbose_name_plural = _("Object changes")


class LdapSyncLog(models.Model):
    """Synchronization process logs"""
    created = models.DateTimeField(_("Sync date"), auto_now_add=True)
    account = models.ForeignKey(LdapAccount, verbose_name=_("LDAP Account"),
                                on_delete=models.CASCADE,
                                null=True)
    status = models.BooleanField(_("Status"), default=False)
    synchronizing = models.BooleanField(_("Synchronizing"), default=False)

    # Total of synchronized objects
    total = models.IntegerField(_("Total"), default=0)

    def __str__(self):
        dt = date_format(self.created)
        return "Log {0} :: Status({1.status}/{1.total})".format(dt, self)

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
