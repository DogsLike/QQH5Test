from django.conf.urls import url,include

from . import views

urlpatterns = [
    url(r'^appsig/$', views.appSig, name='appSig'),
    url(r'^appsigdata/$', views.appSigData, name='appSigData'),
    url(r'^datasig/$', views.dataSig, name='dataSig'),
    url(r'^getprice/$', views.getPrice, name='getPrice'),
    url(r'^sendgoods/$', views.sendGoods, name='sendGoods'),
]