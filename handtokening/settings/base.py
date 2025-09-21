import os
import platform

platform_name = platform.platform()

# Application definition

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "handtokening.clients",
    "handtokening.signing",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "handtokening.clients.authentication.ClientAuthMiddleware",
]

ROOT_URLCONF = "handtokening.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "handtokening.wsgi.application"

# Password validation
# https://docs.djangoproject.com/en/5.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.2/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_TZ = True

FIRST_DAY_OF_WEEK = 1


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.2/howto/static-files/

STATIC_URL = "static/"

# Default primary key field type
# https://docs.djangoproject.com/en/5.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Django rest framework

REST_FRAMEWORK = {
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "handtokening.clients.authentication.ClientAuthentication",
        "rest_framework.authentication.SessionAuthentication",
    ],
}

# Handtokening


def path_config(var_name: str, system_default: dict[str, str]):
    if var_name in os.environ:
        globals()[var_name] = os.environ[var_name]
    else:
        for os_name, path in system_default.items():
            if os_name in platform_name and os.path.exists(path):
                globals()[var_name] = path


path_config(
    "OSSL_PROVIDER_PATH",
    {
        "arch": "/usr/lib/ossl-modules/pkcs11prov.so",
    },
)
path_config(
    "OSSL_ENGINE_PATH",
    {
        "arch": "usr/lib/engines-3/pkcs11.so",
        "deb": "/usr/lib/x86_64-linux-gnu/engines-3/pkcs11.so",
    },
)
path_config(
    "PKCS11_MODULE_PATH",
    {
        "arch": "/usr/lib/opensc-pkcs11.so",
        "deb": "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
    },
)
