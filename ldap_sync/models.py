from django.db import models
from django.conf import settings


class LdapObject(models.Model):
    """Data information for a synchronized ldap object"""

    user = models.OneToOneField(settings.AUTH_USER_MODEL)
    data = models.TextField()

    date_created = models.DateTimeField(auto_now_add=True)
    date_updated = models.DateTimeField(auto_now=True)

    def __unicode__(self):
        return "{0.user}".format(self)


class LdapSyncLog(models.Model):
    """Synchronization process logs"""

    created = models.DateTimeField(auto_now_add=True)
    status = models.BooleanField("Status", default=False)

    # Total of synchronized objects
    total = models.IntegerField("Total", default=0)

    def __unicode__(self):
        return u"{0.status}/{0.total}".format(self)