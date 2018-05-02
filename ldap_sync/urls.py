# coding=utf-8
from django.conf import settings
from django.conf.urls import url, include
from django.views.decorators.cache import never_cache
from django.contrib.auth.decorators import login_required
from . import views

__author__ = 'alex'

cmd_patterns = ([
    url(r'^$', login_required(never_cache(views.SyncView.as_view()),
                              login_url=getattr(settings, "LDAP_SYNC_LOGIN_URL",
                                                settings.LOGIN_URL)),
        name='index'),
    url(r'status/(?P<task_id>.*)', never_cache(views.SyncStatusView.as_view()),
        name='status')
], 'ldap-sync')

urlpatterns = [
    url(r'sync/', include(cmd_patterns)),
]
