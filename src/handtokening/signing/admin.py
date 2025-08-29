from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.html import format_html
from django.template.loader import render_to_string
from django.db.models import Count, Q

from .models import (
    Certificate,
    TimestampServer,
    SigningProfile,
    SigningProfileAccess,
    SigningLog,
    VirusTotalAnalysis,
    VirusTotalEngineResult,
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


UserAdmin.inlines += (SigningProfileAccessInline,)


def render_vt_results_table(results: list[VirusTotalEngineResult]):
    bad_count = sum(r.bad for r in results)
    return render_to_string(
        "signing/vt_results_table.html",
        {"results": results, "bad_count": bad_count},
    )


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
                    "handtokening_version",
                    ("created", "updated", "finished"),
                    ("ip", "user_agent"),
                    ("client", "client_name"),
                    ("signing_profile", "signing_profile_name"),
                    ("certificate", "certificate_name"),
                    "description",
                    "url",
                    "submitted_file_name",
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
    ]

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("vt_analysis")

    def get_fieldsets(self, request, obj):
        fieldsets = self.fieldsets.copy()
        if obj.vt_analysis:
            fieldsets.append(
                (
                    "VirusTotal",
                    {
                        "classes": ["collapse"],
                        "fields": [
                            "vt_url",
                            "vt_analysis",
                            "vt_engine_results",
                        ],
                    },
                ),
            )
        if obj.osslsigncode_command:
            fieldsets.append(
                (
                    "osslsigncode",
                    {
                        "classes": ["collapse"],
                        "fields": [
                            "osslsigncode_command",
                            "osslsigncode_returncode",
                            "osslsigncode_stdout",
                            "osslsigncode_stderr",
                        ],
                    },
                )
            )
        return fieldsets

    @admin.display(description="VirusTotal URL")
    def vt_url(self, obj):
        if obj.vt_analysis_id:
            return format_html(
                '<a href="https://www.virustotal.com/gui/file/{}/detection">View latest in VirusTotal</a>',
                obj.in_file_sha256,
            )
        else:
            return None

    @admin.display(description="Engine results")
    def vt_engine_results(self, obj):
        if obj.vt_analysis:
            results = list(obj.vt_analysis.results.all())
            results.sort(key=lambda r: not r.bad)
            return render_vt_results_table(results)
        else:
            return "-"


@admin.register(VirusTotalAnalysis)
class VirusTotalAnalysisAdmin(ReadOnlyAdminMixin, admin.ModelAdmin):
    list_display = [
        "sha256",
        "date",
        "url",
        "analysis_time",
        "bad_count",
    ]

    fields = [
        "sha256",
        "date",
        "url",
        "analysis_time",
        "engine_results",
    ]

    @admin.display(description="URL")
    def url(self, obj):
        return format_html(
            '<a href="https://www.virustotal.com/gui/file/{}/detection">View latest in VirusTotal</a>',
            obj.sha256,
        )

    @admin.display(description="Engine results")
    def engine_results(self, obj):
        results = list(obj.results.all())
        results.sort(key=lambda r: not r.bad)
        return render_vt_results_table(results)

    @admin.display(ordering="bad_count")
    def bad_count(self, obj):
        return f"{obj.bad_count}/{obj.total_count}"

    def get_queryset(self, request):
        return super().get_queryset(request).annotate(
            bad_count=Count(
                "results",
                filter=Q(results__category__in=VirusTotalEngineResult.bad_categories),
            ),
            total_count=Count("results"),
        )
