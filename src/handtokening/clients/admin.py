from django.utils import timezone
from django.contrib import admin
from django.shortcuts import render

from .models import Client


@admin.register(Client)
class ClientAdmin(admin.ModelAdmin):
    list_display = ["user", "last_secret_rotated", "rotate_every"]
    fields = ["user", "last_secret_rotated", "rotate_every"]
    readonly_fields = ["last_secret_rotated"]

    actions = ["revoke_secrets", "set_secrets", "rotate_secrets"]

    def update_secrets(self, request, queryset, update_fn):
        now = timezone.now()

        clients = list(queryset)
        for client in clients:
            client.do_scheduled_rotate(now)
            update_fn(client)

        Client.objects.bulk_update(
            clients, ["secret1", "secret2", "last_secret_rotated"]
        )

        return render(
            request,
            "clients/secrets-generated.html",
            {"clients": clients},
        )

    @admin.action(description="Assign new secret to client. Clear existing secret")
    def set_secrets(self, request, queryset):
        def update_fn(client: Client):
            client.set_new_secret()
            client.secret2 = None

        return self.update_secrets(request, queryset, update_fn)

    @admin.action(
        description="Rotate new secret into client. Keep last existing secret"
    )
    def rotate_secrets(self, request, queryset):
        def update_fn(client: Client):
            client.secret2 = client.secret1
            client.set_new_secret()

        return self.update_secrets(request, queryset, update_fn)

    @admin.action(description="Revoke all secrets")
    def revoke_secrets(self, request, queryset):
        def update_fn(client: Client):
            client.secret1 = None
            client.secret2 = None

        return self.update_secrets(request, queryset, update_fn)
