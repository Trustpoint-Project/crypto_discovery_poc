from django.urls import path
from . import views

urlpatterns = [
    path('', views.device_list, name='device_list'),
    path('start-scan/', views.start_scan, name='start_scan'), # New URL
]
