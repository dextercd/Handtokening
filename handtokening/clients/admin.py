from django.utils import timezone
from django.contrib import admin
from django.shortcuts import render
from django.db.models import Case, When, Value

from .models import Client, ClientSecret


@admin.register(Client)
class ClientAdmin(admin.ModelAdmin):
    list_display = ["user", "default_secret_duration"]
    fields = ["user", "default_secret_duration"]

    actions = ["revoke_secrets", "add_secrets", "replace_secrets"]

    @admin.action(description="Add new secret keeping existing secrets")
    def add_secrets(self, request, queryset):
        clients = list(queryset)
        for client in clients:
            client.set_new_secret()

        return render(
            request,
            "clients/secrets-generated.html",
            {"clients": clients},
        )

    @admin.action(description="Replace existing secrets with new secret")
    def replace_secrets(self, request, queryset):
        self.revoke_secrets(request, queryset)
        return self.add_secrets(request, queryset)

    @admin.action(description="Revoke all secrets")
    def revoke_secrets(self, request, queryset):
        ClientSecret.objects.filter(client__in=list(queryset)).delete()


@admin.register(ClientSecret)
class ClientSecretAdmin(admin.ModelAdmin):
    list_display = [
        "client",
        "created",
        "valid_for",
        "valid_until",
        "valid",
    ]

    readonly_fields = ["created", "valid"]

    fields = list_display

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return True

    @admin.display(boolean=True, ordering="-valid")
    def valid(self, obj):
        return bool(obj.valid)

    def get_queryset(self, request):
        return (
            super()
            .get_queryset(request)
            .annotate(
                valid=Case(
                    When(valid_until__gt=timezone.now(), then=Value(1)),
                    default=Value(0),
                ),
            )
        )
