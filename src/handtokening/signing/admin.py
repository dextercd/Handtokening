from django.contrib import admin

from .models import (
    Certificate,
    TimestampServer,
    SigningProfile,
    SigningProfileAccess,
    SigningLog,
)
from handtokening.admin import ReadOnlyAdminMixin


@admin.register(Certificate)
class CertificateAdmin(admin.ModelAdmin):
    list_display = ["name", "cert_path", "expires", "is_enabled"]


@admin.register(TimestampServer)
class TimestampServerAdmin(admin.ModelAdmin):
    list_display = ["name", "url", "is_enabled"]


class SigningProfileAccessInline(admin.TabularInline):
    model = SigningProfileAccess
    readonly_fields = ["created"]


@admin.register(SigningProfile)
class SigningProfileAdmin(admin.ModelAdmin):
    list_display = ["name", "created", "updated"]

    inlines = (SigningProfileAccessInline,)


@admin.register(SigningLog)
class SigningLogAdmin(ReadOnlyAdminMixin, admin.ModelAdmin):
    list_display = [
        "client_name",
        "ip",
        "created",
        "submitted_file_name",
        "description",
        "signing_profile_name",
        "certificate_name",
        "result",
    ]

    list_filter = [
        "created",
        "client_name",
        "signing_profile_name",
        "result",
    ]

    fieldsets = [
        (
            None,
            {
                "fields": [
                    ("created", "updated", "finished"),
                    ("ip", "user_agent"),
                    ("client", "client_name"),
                    ("signing_profile", "signing_profile_name"),
                    ("certificate", "certificate_name"),
                    "description",
                    "url",
                    "submitted_file_name",
                    "virus_total_url",
                    "result",
                    "exception",
                ]
            },
        ),
        (
            "Local files",
            {
                "classes": ["collapse"],
                "fields": [
                    "in_path",
                    "in_file_size",
                    "in_file_sha256",
                    "out_path",
                    "out_file_size",
                    "out_file_sha256",
                ],
            },
        ),
        (
            "Logs",
            {
                "classes": ["collapse"],
                "fields": [
                    "osslsigncode_returncode",
                    "osslsigncode_stdout",
                    "osslsigncode_stderr",
                ],
            },
        ),
    ]
