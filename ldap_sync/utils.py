import ctypes
from StringIO import StringIO

import re
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.management import call_command


def get_setting(name, default=None, strict=False):
    if strict and not hasattr(settings, name):
        raise ImproperlyConfigured("%s must be specified in your Django settings" % name)
    return getattr(settings, name, default)


class CeleryWorker(object):
    ERROR_KEY = "ERROR"

    @classmethod
    def get_inspect_status(cls):
        try:
            from celery.task.control import inspect
            insp = inspect()
            d = insp.stats()
            if not d:
                d = {cls.ERROR_KEY: 'No running Celery workers were found.'}
        except IOError as e:
            from errno import errorcode
            msg = "Error connecting to the backend: " + str(e)
            if len(e.args) > 0 and errorcode.get(e.args[0]) == 'ECONNREFUSED':
                msg += ' Server connection refused.'
            d = {cls.ERROR_KEY: msg}
        except ImportError as e:
            d = {cls.ERROR_KEY: str(e)}
        return d

    @classmethod
    def is_running(cls, name=None):
        """Function that needs to somehow determine if celery is running"""
        output = StringIO()
        # noinspection PyBroadException
        try:
            call_command('supervisor', 'status', stdout=output)
        except Exception as err:
            # There is no way to know in this case.
            return False
        if name is None:
            name = 'celery'
        # If found True
        return bool(re.search(r'{}\s+RUNNING'.format(name), output.getvalue()))


class Magic(object):
    dlls = (
        'VCRUNTIME140.DLL',
        'API-MS-WIN-CRT-TIME-L1-1-0.DLL',
        'API-MS-WIN-CRT-STDIO-L1-1-0.DLL',
        'API-MS-WIN-CRT-HEAP-L1-1-0.DLL',
        'API-MS-WIN-CRT-STRING-L1-1-0.DLL',
        'API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL',
        'API-MS-WIN-CRT-UTILITY-L1-1-0.DLL',
        'API-MS-WIN-CRT-CONVERT-L1-1-0.DLL',
        'API-MS-WIN-CRT-FILESYSTEM-L1-1-0.DLL',
        'API-MS-WIN-CRT-LOCALE-L1-1-0.DLL',
        'API-MS-WIN-CRT-ENVIRONMENT-L1-1-0.DLL',
        'API-MS-WIN-CRT-MATH-L1-1-0.DLL'
    )
    magic, loaded = None, False

    @classmethod
    def load(cls):
        """Load lib magic with its dependencies"""
        if cls.loaded:
            return cls.magic
        for libname in cls.dlls:
            try:
                ctypes.CDLL(libname)
            except WindowsError:
                _magic = None
                break
        else:
            try:
                import magic as _magic
            except ImportError:
                _magic = None
        cls.loaded = True
        cls.magic = _magic
        return _magic
