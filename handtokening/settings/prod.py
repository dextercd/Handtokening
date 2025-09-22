from os import environ
from pathlib import Path

from .util import env_bool
from .base import *

DEBUG = env_bool("UNSAFE_DEBUG", False)

state_dir = Path(environ["STATE_DIRECTORY"])
config_dir = Path(environ["CONFIGURATION_DIRECTORY"])
home = Path(environ["HOME"])

with open(state_dir / "django-secret") as f:
    SECRET_KEY = f.read().strip()

if (vt_path := config_dir / "vt-api").exists():
    with open(vt_path) as f:
        VIRUS_TOTAL_API_KEY = f.read().strip()

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": state_dir / "db.sqlite3",
    }
}

if "STATIC_ROOT" in environ:
    STATIC_ROOT = environ["STATIC_ROOT"]
else:
    STATIC_ROOT = home / "static"

if "STATIC_URL" in environ:
    STATIC_URL = environ["STATIC_URL"]

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
        "level": environ.get("DJANGO_LOG_LEVEL") or "WARNING",
    },
}

PIN_COMMS_LOCATION = environ.get("RUNTIME_DIRECTORY")

STATE_DIRECTORY = state_dir
TEST_CERTIFICATE_DIRECTORY = state_dir / "certs"

# Security and server configuration related settings

# https://github.com/un33k/django-ipware/tree/master#precedence-order
if "IPWARE_META_PRECEDENCE_ORDER" in environ:
    IPWARE_META_PRECEDENCE_ORDER = environ["IPWARE_META_PRECEDENCE_ORDER"].split(",")
else:
    IPWARE_META_PRECEDENCE_ORDER = ["REMOTE_ADDR"]

DISABLE_SERVER_SIDE_CURSORS = env_bool("DISABLE_SERVER_SIDE_CURSORS", False)

if "ALLOWED_HOSTS" in environ:
    ALLOWED_HOSTS = environ["ALLOWED_HOSTS"].split(",")

USE_X_FORWARDED_HOST = env_bool("USE_X_FORWARDED_HOST", False)
USE_X_FORWARDED_PORT = env_bool("USE_X_FORWARDED_PORT", False)

LANGUAGE_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True
SESSION_COOKIE_HTTPONLY = True

cookie_path = environ.get("SCRIPT_NAME") or "/"
LANGUAGE_COOKIE_PATH = cookie_path
CSRF_COOKIE_PATH = cookie_path
SESSION_COOKIE_PATH = cookie_path

samesite = environ.get("SAMESITE") or "Lax"
LANGUAGE_COOKIE_SAMESITE = samesite
CSRF_COOKIE_SAMESITE = samesite
SESSION_COOKIE_SAMESITE = samesite

cookie_secure = env_bool("COOKIE_SECURE", False)
LANGUAGE_COOKIE_SECURE = cookie_secure
CSRF_COOKIE_SECURE = cookie_secure
SESSION_COOKIE_SECURE = cookie_secure

if "CSRF_COOKIE_AGE" in environ:
    CSRF_COOKIE_AGE = int(environ["CSRF_COOKIE_AGE"])

if "SESSION_COOKIE_AGE" in environ:
    SESSION_COOKIE_AGE = int(environ["SESSION_COOKIE_AGE"])

if "LANGUAGE_COOKIE_NAME" in environ:
    LANGUAGE_COOKIE_NAME = environ["LANGUAGE_COOKIE_NAME"]

if "CSRF_COOKIE_NAME" in environ:
    CSRF_COOKIE_NAME = environ["CSRF_COOKIE_NAME"]

if "SESSION_COOKIE_NAME" in environ:
    SESSION_COOKIE_NAME = environ["SESSION_COOKIE_NAME"]

if "CSRF_HEADER_NAME" in environ:
    CSRF_HEADER_NAME = environ["CSRF_HEADER_NAME"]

if "CSRF_TRUSTED_ORIGINS" in environ:
    CSRF_TRUSTED_ORIGINS = environ["CSRF_TRUSTED_ORIGINS"].split(",")

SESSION_EXPIRE_AT_BROWSER_CLOSE = env_bool("SESSION_EXPIRE_AT_BROWSER_CLOSE", False)
CSRF_USE_SESSIONS = env_bool("CSRF_USE_SESSIONS", False)

SECURE_HSTS_INCLUDE_SUBDOMAINS = env_bool("SECURE_HSTS_INCLUDE_SUBDOMAINS", False)
SECURE_HSTS_PRELOAD = env_bool("SECURE_HSTS_PRELOAD", False)

if "SECURE_HSTS_SECONDS" in environ:
    SECURE_HSTS_SECONDS = int(environ["SECURE_HSTS_SECONDS"])

if "SECURE_PROXY_SSL_HEADER" in environ:
    SECURE_PROXY_SSL_HEADER = tuple(
        v.strip() for v in environ["SECURE_PROXY_SSL_HEADER"].split(",")
    )

if "SECURE_SSL_HOST" in environ:
    SECURE_SSL_HOST = environ["SECURE_SSL_HOST"]

SECURE_SSL_REDIRECT = env_bool("SECURE_SSL_REDIRECT", False)
