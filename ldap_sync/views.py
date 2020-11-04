import importlib

from celery import current_app
from celery.result import AsyncResult
from django.conf import settings
from django.contrib.auth import get_user_model
from django.http import JsonResponse
from django.shortcuts import render
from django.utils.translation import ugettext as _
from django.views.generic import View

from .utils import CeleryWorker

User = get_user_model()


class SyncView(View):
    """Execution of tasks"""

    template = getattr(settings, "LDAP_SYNC_VIEW_INDEX_TEMPLATE",
                       'ldap_sync/index.html')

    template_status = getattr(settings, "LDAP_SYNC_VIEW_STATUS_TEMPLATE",
                              'ldap_sync/status.html')

    def __init__(self, *args, **kwargs):
        super(SyncView, self).__init__(*args, **kwargs)

        task = getattr(settings, "LDAP_SYNC_TASK", "ldap_sync.tasks.syncldap")

        package, task = task.rsplit('.', 1)

        self.task = getattr(importlib.import_module(package), task)

        self.celery_available = CeleryWorker.is_running()

    def get(self, request):
        return render(request, self.template, context={
            'celery': self.celery_available
        })

    def post(self, request, **kwargs):
        async_result = self.task.delay()
        return render(request, self.template_status, context={
            'async_result': async_result,
            'celery': self.celery_available
        })


class SyncStatusView(View):
    """Checking the status of a previously executed task"""
    def __init__(self, *args, **kwargs):
        super(SyncStatusView, self).__init__(*args, **kwargs)
        self.celery_available = CeleryWorker.is_running()

    def get(self, request, **kwargs):
        """Reports task status"""
        task_id = str(kwargs.get("task_id"))
        async_result = AsyncResult(id=task_id, app=current_app)
        data = {
            'task': {
                'id': async_result.id,
                'ready': async_result.ready(),
                'celery': self.celery_available
            }
        }
        if async_result.failed():
            data['task']['failed'] = True
            if request.user.is_authenticated and request.user.is_superuser:
                data['task']['traceback'] = async_result.traceback
            else:
                data['task']['traceback'] = _("Sync error")
        else:
            data['task']['failed'] = False
            data['task']['output'] = {
                'user_count': User.objects.all().count(),
                'label': _("User count")
            }
        if not self.celery_available:  # stop
            data['task']['ready'] = True
            data['task']['failed'] = True
            data['task']['traceback'] = _("celery: unavailable service")

        return JsonResponse(data)
