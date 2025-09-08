from os import environ
from pathlib import Path

from .base import *

DEBUG = False

state_dir = Path(environ["STATE_DIRECTORY"])
config_dir = Path(environ["CONFIGURATION_DIRECTORY"])
home = Path(environ["HOME"])

with open(state_dir / "django-secret") as f:
    SECRET_KEY = f.read().strip()

if (vt_path := config_dir / "vt-api").exists():
    with open(vt_path) as f:
        VIRUS_TOTAL_API_KEY = f.read().strip()

if "ALLOWED_HOSTS" in environ:
    ALLOWED_HOSTS = environ["ALLOWED_HOSTS"].split(",")

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": state_dir / "db.sqlite3",
    }
}

STATIC_ROOT = home / "static"

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "WARNING",
    },
}

# https://github.com/un33k/django-ipware/tree/master#precedence-order
if "IPWARE_META_PRECEDENCE_ORDER" in environ:
    IPWARE_META_PRECEDENCE_ORDER = environ["IPWARE_META_PRECEDENCE_ORDER"].split(",")
else:
    IPWARE_META_PRECEDENCE_ORDER = ["REMOTE_ADDR"]

PIN_COMMS_LOCATION = environ.get("RUNTIME_DIRECTORY")

STATE_DIRECTORY = str(state_dir)
