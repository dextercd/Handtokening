from datetime import datetime
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

    # secret1 shifts to secret2 after now() > last_rotate + secret_lifetime/2
    # a new secret is placed in secret1 and the old secret2 is discarded
    secret1 = models.CharField(null=True)
    secret2 = models.CharField(null=True)

    new_secret = None

    def set_new_secret(self):
        self.new_secret = new_secret()
        self.secret1 = encode_secret(self.new_secret)
        self.last_secret_rotated = timezone.now()

    last_secret_rotated = models.DateTimeField(default=timezone.now)
    rotate_every = models.DurationField()

    def do_scheduled_rotate(self, now: datetime | None = None):
        now = now or timezone.now()
        if now > self.last_secret_rotated + self.rotate_every * 2:
            self.secret1 = self.secret2 = None
            self.last_secret_rotated = now
            return True
        elif now > self.last_secret_rotated + self.rotate_every:
            self.secret2 = self.secret1
            self.secret1 = None
            self.last_secret_rotated = now
            return True
        else:
            return False

    # TODO: Workload OIDC option


# Certificate <- Certificate Group Member -> SigningProfile <- Certificate Group Access -> Client
