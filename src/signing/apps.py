import glob
import os

from django.apps import AppConfig


class CertificatesConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "signing"

    def ready(self):
        for r in glob.glob("/tmp/handtokening-requests/*"):
            try:
                os.remove(r)
            except Exception as exc:
                pass

        for r in glob.glob("/tmp/handtokening-responses/*"):
            try:
                os.remove(r)
            except Exception as exc:
                pass
