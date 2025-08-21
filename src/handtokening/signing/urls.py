from django.urls import path

from .views import SignView


app_name = "signing"
urlpatterns = [path("sign", SignView.as_view())]
