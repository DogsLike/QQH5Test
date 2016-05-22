from django.conf.urls import url,include

from . import views

urlpatterns = [
    url(r'^appsig/$', views.appSig, name='appSig'),
    url(r'^datasig/$', views.dataSig, name='dataSig'),
]