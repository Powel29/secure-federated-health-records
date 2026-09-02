"""Django settings for the three web portals (C16, ADR-0014/0021).

Boundary (ADR-0014/0021): the portals store data and identify users; they never
decide access or decrypt. Django's tables live in the ``portal`` schema of the
shared Postgres; the P0-8 store tables are reached through the ``store`` alias
with a **read-only** role, so the portal can read the store live but never write
it. All store *writes* go through the crypto/ingest service, never Django.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Dev-only fallback: a random key per start (never a committed secret). Set
# DJANGO_SECRET_KEY in any real deployment.
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY") or secrets.token_urlsafe(32)
DEBUG = os.environ.get("DJANGO_DEBUG", "1") == "1"
ALLOWED_HOSTS = (
    ["*"] if DEBUG else os.environ.get("DJANGO_ALLOWED_HOSTS", "").split(",")
)

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "accounts",
    "patient",
    "clinician",
    "admin_audit",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
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

WSGI_APPLICATION = "config.wsgi.application"

# --- Databases: one Postgres, two roles (ADR-0021) --------------------------
_DB_HOST = os.environ.get("PORTAL_DB_HOST", "localhost")
_DB_PORT = os.environ.get("PORTAL_DB_PORT", "55432")
_DB_NAME = os.environ.get("PORTAL_DB_NAME", "ehr_test")

DATABASES = {
    # Django's own tables live in the `portal` schema.
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": _DB_NAME,
        "HOST": _DB_HOST,
        "PORT": _DB_PORT,
        "USER": os.environ.get("PORTAL_DB_USER", "postgres"),
        "PASSWORD": os.environ.get("PORTAL_DB_PASSWORD", ""),
        "OPTIONS": {"options": "-c search_path=portal,public"},
    },
    # Read-only window onto the P0-8 store tables. The `portal_ro` role has
    # SELECT only -- the boundary is a Postgres permission, not a convention.
    "store": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": _DB_NAME,
        "HOST": _DB_HOST,
        "PORT": _DB_PORT,
        "USER": os.environ.get("STORE_DB_USER", "portal_ro"),
        "PASSWORD": os.environ.get("STORE_DB_PASSWORD", ""),
        "OPTIONS": {"options": "-c search_path=public"},
    },
}

# Never let the ORM migrate or write anything but `default`.
DATABASE_ROUTERS = ["config.routers.PortalRouter"]

AUTH_PASSWORD_VALIDATORS: list[dict[str, str]] = []

LOGIN_URL = "/accounts/login/"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/accounts/login/"

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
