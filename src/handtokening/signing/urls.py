from django.urls import path, include
from rest_framework import routers

from .views import SignView


app_name = "signing"
urlpatterns = [path("sign", SignView.as_view())]
