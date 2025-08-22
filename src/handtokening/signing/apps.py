import logging
from pathlib import Path

from django.apps import AppConfig
from .conf import config


logger = logging.getLogger(__name__)


def try_create_dir(path: Path, mode=0o755):
    try:
        path.mkdir(mode=mode, parents=True, exist_ok=True)
    except Exception as exc:
        logging.error(f"Tried to create path '{path}' but got error: {exc}")


def try_clear_dir(path: Path):
    for r in path.glob("*"):
        try:
            r.unlink()
        except Exception as exc:
            logging.error(f"Tried to delete '{r}' but got error: {exc}")


class CertificatesConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "handtokening.signing"

    def ready(self):
        try_create_dir(config.PIN_COMMS_LOCATION, mode=0o775)
        try_create_dir(config.PIN_COMMS_LOCATION / "requests", mode=0o775)
        try_create_dir(config.PIN_COMMS_LOCATION / "responses", mode=0o775)

        try_clear_dir(config.PIN_COMMS_LOCATION / "requests")
        try_clear_dir(config.PIN_COMMS_LOCATION / "responses")

        try_create_dir(config.STATE_DIRECTORY / "in")
        try_create_dir(config.STATE_DIRECTORY / "out")
