# csrfscanner/urls.py
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),  # Django admin
    path('', include('scannerapp.urls')),  # Include URLs from scannerapp
]

