from datetime import timedelta, datetime, timezone
import subprocess

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.db import transaction
from django.contrib.auth.hashers import make_password

from handtokening.clients.models import Client
from handtokening.signing.models import SigningProfile, Certificate
from handtokening.signing.conf import config


User = get_user_model()


class Command(BaseCommand):
    help = "Create test signing profile, client, and certificate"

    @transaction.atomic
    def handle(self, *args, **kwargs):
        signing_profile, _ = SigningProfile.objects.get_or_create(name="test-signing")

        user, new_user = User.objects.get_or_create(
            username="test",
            defaults={
                "password": make_password(None),
            },
        )

        client, _ = Client.objects.get_or_create(
            user=user,
            defaults={
                "rotate_every": timedelta(days=2),
            },
        )

        if new_user:
            signing_profile.users_with_access.add(user)

        not_before = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(
            hours=-1
        )
        not_after = not_before + timedelta(days=3653, seconds=-1)

        label = str(not_before.year // 10 * 10).zfill(4)
        if not_before.month <= 6:
            label += "HD1"
        else:
            label += "HD2"

        cert_path = config.TEST_CERTIFICATE_DIRECTORY / f"test_cert_{label}.pem"
        key_path = config.TEST_CERTIFICATE_DIRECTORY / f"test_key_{label}.key"

        certificate, new_cert = Certificate.objects.get_or_create(
            name=f"Test Certificate {label}",
            defaults={
                "cert_path": str(cert_path),
                "key_path": str(key_path),
                "expires": not_after,
            },
        )

        if new_cert:
            # fmt: off
            subprocess.run(
                [
                    "openssl", "req", "-x509",
                    "-noenc",
                    "-newkey", "rsa:4096",
                    "-subj", f"/CN=Handtokening Test Sign {label}",
                    "-not_before", not_before.strftime("%Y%m%d%H%M%SZ"),
                    "-not_after", not_after.strftime("%Y%m%d%H%M%SZ"),
                    "-addext", "basicConstraints=critical,CA:TRUE",
                    "-addext", "keyUsage=digitalSignature",
                    "-addext", "extendedKeyUsage=codeSigning",
                    "-out", str(cert_path),
                    "-keyout", str(key_path),
                ],
                check=True
            )
            # fmt: on

            signing_profile.certificates.add(certificate)
