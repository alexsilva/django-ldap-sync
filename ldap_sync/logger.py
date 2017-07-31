import logging

from ldap_sync.models import LdapSyncLog, LdapSyncLogMeta


class Logger(object):
    def __init__(self):
        self.slog = LdapSyncLog.objects.create()

    def log(self, msg, level=logging.INFO):
        return LdapSyncLogMeta.objects.create(
            log=self.slog,
            level=level,
            text=msg)

    def set_total(self, value):
        self.slog.total = value
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