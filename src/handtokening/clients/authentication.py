from base64 import b64decode
from functools import lru_cache
import hmac

from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.http import HttpRequest
from rest_framework import authentication

from .models import new_secret, encode_secret


User = get_user_model()


@lru_cache
def fake_pass():
    return encode_secret(new_secret())


# Django authentication
class ClientAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request: HttpRequest):
        auth: str = request.META.get("HTTP_AUTHORIZATION") or ""
        if auth.startswith("Basic "):
            name, _, text_pwd = (
                b64decode(auth.removeprefix("Basic ").strip()).decode().partition(":")
            )
            user = (
                User.objects.filter(is_active=True, client__isnull=False, username=name)
                .select_related("client")
                .first()
            )
            encoded_pwd = encode_secret(text_pwd)

            # Prevent timing information leak with fake pass check
            secret1 = secret2 = fake_pass()

            if user:
                if user.client.do_scheduled_rotate():
                    user.client.save()

                if user.client.secret1:
                    secret1 = user.client.secret1
                if user.client.secret2:
                    secret2 = user.client.secret2

            check1 = hmac.compare_digest(encoded_pwd, secret1)
            check2 = hmac.compare_digest(encoded_pwd, secret2)

            if check1 or check2:
                # TODO: revoke credentials if http
                request.user = user
            else:
                raise PermissionDenied("Client not found or bad password")

        return self.get_response(request)


# DRF authentication
class ClientAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        if getattr(request._request, "user", None) and getattr(
            request._request.user, "client", None
        ):
            return (request._request.user, None)
        return None
