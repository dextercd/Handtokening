from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from handtokening.signing.models import TimestampServer


standard_list = [
    ("HARICA", "http://ts.harica.gr"),
    ("DigiCert", "http://timestamp.digicert.com"),
    ("Sectigo", "http://timestamp.sectigo.com"),
    ("SSL.COM", "http://ts.ssl.com"),
    ("GlobalSign", "http://rfc3161timestamp.globalsign.com/advanced"),
    ("Microsoft", "http://timestamp.acs.microsoft.com"),
]


class Command(BaseCommand):
    help = "Add a timestamp server"

    def add_arguments(self, parser):
        parser.add_argument("name", nargs="?")
        parser.add_argument("url", nargs="?")

        parser.add_argument(
            "--add-standard-servers",
            action="store_true",
            help="Add list of standard timestamp servers",
        )

    @transaction.atomic
    def handle(self, *args, **kwargs):
        to_create = []

        if kwargs["add_standard_servers"]:
            to_create.extend(standard_list)

        if kwargs.get("name"):
            if not kwargs.get("url"):
                raise CommandError("Must provide both name and url")
            else:
                to_create.append((kwargs["name"], kwargs["url"]))

        tss = [TimestampServer(name=ts[0], url=ts[1]) for ts in to_create]
        for ts in tss:
            ts.full_clean(validate_unique=False)

        TimestampServer.objects.bulk_create(
            tss, update_conflicts=True, update_fields=["url"], unique_fields=["name"]
        )

        print(f"Added or updated {len(tss)} servers.")
