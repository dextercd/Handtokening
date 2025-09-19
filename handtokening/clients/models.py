import hashlib
import secrets

from django.conf import settings
from django.db import models
from django.utils import timezone


def new_secret():
    # With this prefix it gets picked up by gitleaks
    return "htkey," + secrets.token_urlsafe(20)


def encode_secret(s: str):
    return hashlib.sha256(s.encode()).hexdigest()


class Client(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, primary_key=True, on_delete=models.CASCADE
    )
    default_secret_duration = models.DurationField()

    new_secret = None

    def __str__(self):
        if Client.user.is_cached(self):
            return self.user.username
        elif hasattr(self, "username"):
            # For when added with .annotate(username=F("user__username"))
            return self.username
        else:
            return str(self.pk)

    def set_new_secret(self):
        self.new_secret = new_secret()
        now = timezone.now()
        ClientSecret.objects.create(
            client=self,
            secret=encode_secret(self.new_secret),
            created=now,
            valid_for=self.default_secret_duration,
            valid_until=now + self.default_secret_duration,
        )


class ClientSecret(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    secret = models.CharField(null=True)
    created = models.DateTimeField(auto_now_add=True)
    valid_for = models.DurationField()
    valid_until = models.DateTimeField()
