from django.core.management import call_command

from celery import shared_task


@shared_task(ignore_result=False,
             track_started=True)
def syncldap():
    """
    Call the appropriate management command to synchronize the LDAP users
    with the local database.
    """
    call_command('syncldap')
