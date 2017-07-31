from django.db import models
from django.conf import settings
import logging

from django.utils.text import Truncator


class LdapObject(models.Model):
    """Data information for a synchronized ldap object"""

    user = models.OneToOneField(settings.AUTH_USER_MODEL)
    data = models.TextField()

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    def __unicode__(self):
        return u"{0.user}".format(self)


class LdapSyncLog(models.Model):
    """Synchronization process logs"""

    created = models.DateTimeField(auto_now_add=True)
    status = models.BooleanField("Status", default=False)

    # Total of synchronized objects
    total = models.IntegerField("Total", default=0)

    def __unicode__(self):
        return u"{0.status}/{0.total}".format(self)


class LdapSyncLogMeta(models.Model):
    log = models.ForeignKey(LdapSyncLog)
    level = models.SmallIntegerField()
    text = models.TextField()

    def __unicode__(self):
        text = Truncator(self.text).chars(30, html=True)
        return u"{} {}".format(logging.getLevelName(self.level), text)
