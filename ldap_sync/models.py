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
