from django.contrib.auth import get_user_model
from django.db.models.signals import post_save
from django.dispatch import receiver
from ldap_sync.models import LdapObject

UserModel = get_user_model()


@receiver(post_save, sender=UserModel, dispatch_uid="sync_ldapobject")
def sync_ldapobject(sender, **kwargs):
	instance = kwargs['instance']
	try:
		LdapObject.objects.filter(
			user=instance
		).update(is_active=instance.is_active)
	except LdapObject.DoesNotExist:
		...


def ready(self):
	...
