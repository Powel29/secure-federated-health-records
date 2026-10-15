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
# Off unless asked for (review F42): the local demo launcher sets
# DJANGO_DEBUG=1 explicitly; anything else runs without debug pages.
DEBUG = os.environ.get("DJANGO_DEBUG", "0") == "1"
ALLOWED_HOSTS = (
    ["*"]
    if DEBUG
    else os.environ.get("DJANGO_ALLOWED_HOSTS", "127.0.0.1,localhost").split(",")
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
    "ledger",
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
                "portal_core.context.product",
            ],
            "builtins": ["portal_core.display"],
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
STATICFILES_DIRS = [BASE_DIR / "static"]
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# --- Federation services the portals talk to (ADR-0043) ---------------------
# Every URL comes from configuration, never from a request (CONVENTIONS.md §2
# rule 8). The portals call: the Key Custodian for anything that needs a key
# on the caller's side; facility nodes for consent-grant submission, discovery
# and emergency search (no keys in those bodies); the Audit Service to append
# portal-originated events (patient.lookup, patient.notification) and to read
# chain state. Defaults match deploy/run_local.py's Path A ports.


def _url_map(raw: str) -> dict[str, str]:
    pairs: dict[str, str] = {}
    for item in raw.split(","):
        key, _, value = item.strip().partition("=")
        if key and value:
            pairs[key.strip()] = value.strip().rstrip("/")
    return pairs


CUSTODIAN_URL = os.environ.get("CUSTODIAN_URL", "http://127.0.0.1:8030").rstrip("/")
AUDIT_SERVICE_URL = os.environ.get("AUDIT_SERVICE_URL", "http://127.0.0.1:8020").rstrip(
    "/"
)
FACILITY_URLS = _url_map(
    os.environ.get(
        "FACILITY_URLS",
        "facility-a=http://127.0.0.1:8001,facility-b=http://127.0.0.1:8002",
    )
)
AUTHORITY_URLS = _url_map(
    os.environ.get(
        "AUTHORITY_URLS",
        "authority-med=http://127.0.0.1:8010,authority-net=http://127.0.0.1:8011",
    )
)
SERVICE_TIMEOUT_SECONDS = float(os.environ.get("SERVICE_TIMEOUT_SECONDS", "8"))
# The portal's own service identity (ADR-0066): it signs every call the portal
# makes, so a service can tell the portal from any other caller. It is not a
# subject's key and opens nothing (ADR-0014). Unset, every call is refused.
SERVICE_KEY_FILE = os.environ.get("SERVICE_KEY_FILE", "")
SERVICE_CERT_FILE = os.environ.get("SERVICE_CERT_FILE", "")
# Break-glass time-box the clinician portal requests, in seconds (ADR-0056).
# Four hours by default; request 60-120 seconds explicitly for a timer demo.
EMERGENCY_DURATION_SECONDS = float(
    os.environ.get("EMERGENCY_DURATION_SECONDS", "14400")
)
# Lifetime of each signed emergency assertion; the custodian caps it at 15 min.
ASSERTION_TTL_SECONDS = int(os.environ.get("ASSERTION_TTL_SECONDS", "120"))
PRODUCT_NAME = os.environ.get("PORTAL_PRODUCT_NAME", "CUSTOS")
