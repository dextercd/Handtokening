import glob
import os

from django.apps import AppConfig
from .conf import config


class CertificatesConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "handtokening.signing"

    def ready(self):
        subdirs = ["", "requests", "responses"]
        for subdir in subdirs:
            try:
                (config.PIN_COMMS_LOCATION / subdir).mkdir(mode=0o775, exist_ok=True)
            except Exception:
                pass

        for r in (config.PIN_COMMS_LOCATION / "requests").glob("*"):
            try:
                r.unlink()
            except Exception:
                pass

        for r in (config.PIN_COMMS_LOCATION / "responses").glob("*"):
            try:
                r.unlink()
            except Exception:
                pass
