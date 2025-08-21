from os import environ
from pathlib import Path

from .base import *

home = Path(environ["HOME"])

with open(home / "data/django-secret") as f:
    SECRET_KEY = f.read().strip()

DEBUG = False

if "ALLOWED_HOSTS" in environ:
    ALLOWED_HOSTS = environ["ALLOWED_HOSTS"].split(",")

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": home / "data/db.sqlite3",
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
