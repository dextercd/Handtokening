from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from handtokening.clients.models import Client, ClientSecret


class Command(BaseCommand):
    help = "Rotate a client's secrets"

    def add_arguments(self, parser):
        parser.add_argument("name")

        parser.set_defaults(mode="new_secret")

        parser.add_argument(
            "--clear-secrets",
            action="store_const",
            dest="mode",
            const="clear",
        )

    @transaction.atomic
    def handle(self, *args, **kwargs):
        client = Client.objects.filter(user__username=kwargs["name"]).first()
        if not client:
            raise CommandError(f"Couldn't find client with username {kwargs['name']}")

        if kwargs["mode"] == "new_secret":
            client.set_new_secret()
            client.save()
            print(f"New secret: {client.new_secret}")
        elif kwargs["mode"] == "clear":
            ClientSecret.objects.filter(client=client).delete()
            print("Secrets cleared")
        else:
            raise CommandError(f"Unknown mode '{kwargs['mode']}'")
