import importlib

from celery.result import AsyncResult
from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import render
from django.views.generic import View
from django.contrib.auth import get_user_model
from celery import current_app

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

    def get(self, request):
        return render(request, self.template)

    def post(self, request, **kwargs):
        async_result = self.task.delay()
        return render(request, self.template_status, context={
            'async_result': async_result
        })


class SyncStatusView(View):
    """Checking the status of a previously executed task"""
    def get(self, request, **kwargs):
        """Reports task status"""
        task_id = str(kwargs.get("task_id"))
        async_result = AsyncResult(id=task_id, app=current_app)
        data = {
            'task': {
                'id': async_result.id,
                'ready': async_result.ready(),
            }
        }
        if async_result.failed():
            data['task']['failed'] = True
            data['task']['traceback'] = async_result.traceback
        else:
            data['task']['failed'] = False
            data['task']['output'] = {
                'user_count': User.objects.all().count(),
                'label': "User count"
            }
        return JsonResponse(data)
