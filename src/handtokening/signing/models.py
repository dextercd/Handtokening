from functools import lru_cache
import importlib.metadata

from django.conf import settings
from django.db import models

from handtokening.clients.models import Client


@lru_cache
def _get_handtokening_version():
    return importlib.metadata.version("handtokening")


class Certificate(models.Model):
    name = models.CharField(unique=True)
    cert_path = models.CharField()
    key_path = models.CharField()
    is_pkcs11 = models.BooleanField(default=False)
    expires = models.DateTimeField()
    pkcs11_module = models.CharField(null=True, blank=True)
    ossl_provider = models.CharField(null=True, blank=True)
    is_enabled = models.BooleanField(default=True)

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Certificate: {self.id} {self.name}"


class TimestampServer(models.Model):
    name = models.CharField(unique=True)
    url = models.URLField()
    is_enabled = models.BooleanField(default=True)

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"TimestampServer: {self.id} {self.name}"


class SigningProfile(models.Model):
    name = models.CharField(unique=True)

    certificates = models.ManyToManyField(Certificate, blank=True, related_name="+")
    timestamp_servers = models.ManyToManyField(
        TimestampServer, blank=True, related_name="+"
    )

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    users_with_access = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        through="SigningProfileAccess",
        blank=True,
        related_name="signing_profiles",
    )

    def __str__(self):
        return f"SigningProfile: {self.id} {self.name}"


class SigningProfileAccess(models.Model):
    signing_profile = models.ForeignKey(SigningProfile, on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    created = models.DateTimeField(auto_now_add=True)


class SigningLog(models.Model):
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    finished = models.DateTimeField(null=True, blank=True)

    handtokening_version = models.CharField(default=_get_handtokening_version)

    ip = models.GenericIPAddressField()
    user_agent = models.CharField(null=True, blank=True)

    client = models.ForeignKey(Client, null=True, blank=True, on_delete=models.SET_NULL)
    client_name = models.CharField()

    signing_profile = models.ForeignKey(
        SigningProfile, null=True, blank=True, on_delete=models.SET_NULL
    )
    signing_profile_name = models.CharField(null=True, blank=True)
    certificate = models.ForeignKey(
        Certificate, null=True, blank=True, on_delete=models.SET_NULL
    )
    certificate_name = models.CharField(null=True, blank=True)
    description = models.CharField(null=True, blank=True)
    url = models.CharField(null=True, blank=True)

    submitted_file_name = models.CharField(null=True, blank=True)
    in_path = models.CharField(null=True, blank=True)
    in_file_size = models.BigIntegerField(null=True, blank=True)
    in_file_sha256 = models.CharField(null=True, blank=True)

    out_path = models.CharField(null=True, blank=True)
    out_file_size = models.BigIntegerField(null=True, blank=True)
    out_file_sha256 = models.CharField(null=True, blank=True)

    osslsigncode_command = models.CharField(null=True, blank=True)

    osslsigncode_returncode = models.IntegerField(null=True, blank=True)
    osslsigncode_stdout = models.TextField(null=True, blank=True)
    osslsigncode_stderr = models.TextField(null=True, blank=True)

    virus_total_url = models.URLField(null=True, blank=True)

    class Result(models.TextChoices):
        PENDING = "pending", "Pending"
        SUCCESS = "success", "Success"
        SIGN_ERROR = "sign-error", "Signing Error"
        NO_CERTIFICATES = "no-certs", "No Certificates"
        AV_POSITIVE = "av-positive", "AV Positive"
        UNSUPPORTED_EXTENSION = (
            "unsupported-file-extension",
            "Unsupported File Extension",
        )
        INTERNAL_ERROR = "internal-error", "Internal Error"
        CANCELLED = "cancelled", "Cancelled"
        PIN_TIMEOUT = "pin-timeout", "PIN Timeout"

    result = models.CharField(choices=Result.choices)
    exception = models.CharField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["-created"]),
            models.Index(fields=["client_name", "-created"]),
            models.Index(fields=["signing_profile_name", "-created"]),
        ]
        ordering = ["-created"]
