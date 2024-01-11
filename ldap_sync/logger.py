# coding=utf-8
import logging

from ldap_sync.models import LdapSyncLog, LdapSyncLogMeta
from ldap_sync.models import LdapObjectLog


def user_log_message(ldap_object, message, **options):
    """Creates a log message for the synchronized user"""
    max_length = LdapObjectLog._meta.get_field('message').max_length
    text_truncated = len(message) > max_length
    return LdapObjectLog.objects.create(
        ldap_object=ldap_object,
        message=message[:max_length - (3 if text_truncated else 0)] + ("..." if text_truncated else ""),
        **options
    )


class Logger:
    def __init__(self, account=None):
        self.slog = LdapSyncLog.objects.create(account=account)

    def log(self, msg, level=logging.INFO):
        return LdapSyncLogMeta.objects.create(
            log=self.slog,
            level=level,
            text=msg)

    def set_total(self, value):
        self.slog.total = value
        self.slog.save()

    def set_synchronizing(self, value):
        self.slog.synchronizing = value
        self.slog.save()

    def set_status(self, value):
        self.slog.status = value
        self.slog.save()

    def info(self, msg):
        self.log(msg)

    def error(self, msg):
        self.log(msg, logging.ERROR)

    def debug(self, msg):
        self.log(msg, logging.DEBUG)

    def warning(self, msg):
        self.log(msg, logging.WARNING)
