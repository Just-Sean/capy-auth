"""The smallest Django project that can run this module's tests.

It stands in for "any project that installs the module". If the module only
works inside one particular project, these tests fail.

Database: SQLite in memory by default, no setup needed. To test against
Postgres (for Postgres-only features), set DATABASE_URL (the README's "Develop it"
starts this database, with a login like CI's):
    DATABASE_URL=postgres://module:module@localhost:5433/module_tests uv run pytest

User model: Django's own auth.User by default. TEST_USER_MODEL=email switches to a
copy of capy-project's user (email required, unique ignoring case, stored lowercase),
so the module is tested with both:
    TEST_USER_MODEL=email uv run pytest
"""

import os
import secrets
from pathlib import Path

import dj_database_url
from django.core.exceptions import ImproperlyConfigured
from django.utils.csp import CSP

SECRET_KEY = secrets.token_urlsafe(50)  # a new one every run: nothing to keep secret
DEBUG = False
ALLOWED_HOSTS = ["testserver"]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "capy_auth",
    "allauth",
    "allauth.account",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.csp.ContentSecurityPolicyMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "allauth.account.middleware.AccountMiddleware",
]

# As the README tells a project: allauth's backend for logins, Django's for the admin's
# login until capy-auth sends it through allauth. Differs from capy-project on purpose,
# for now: capy-project also runs its per-address login limit and django-axes first
# (config/settings/users.py); the capy-auth feature that makes allauth work with them
# adds them here too.
AUTHENTICATION_BACKENDS = [
    "allauth.account.auth_backends.AuthenticationBackend",
    "django.contrib.auth.backends.ModelBackend",
]

# capy-auth's allauth settings, exactly as the README's "Add it to a project" gives them.
ACCOUNT_ADAPTER = "capy_auth.account.adapter.AccountAdapter"
ACCOUNT_LOGIN_METHODS = {"email"}
ACCOUNT_SIGNUP_FIELDS = ["email*", "password1*", "password2*"]
ACCOUNT_EMAIL_VERIFICATION = "mandatory"
ACCOUNT_EMAIL_VERIFICATION_BY_CODE_ENABLED = True
ACCOUNT_SESSION_REMEMBER = True
ACCOUNT_EMAIL_NOTIFICATIONS = True
PASSWORD_RESET_TIMEOUT = 60 * 60  # reset links work for 1 hour

# capy-project's password rules (config/settings/users.py).
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 12},
    },
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# Email, kept in memory (Django's test runner also collects it in mail.outbox).
MAILERS = {"default": {"BACKEND": "django.core.mail.backends.locmem.EmailBackend"}}
DEFAULT_FROM_EMAIL = "accounts@example.com"

ROOT_URLCONF = "tests.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        # tests/templates holds a copy of capy-project's base.html and layout.html,
        # which the module's pages extend.
        "DIRS": [Path(__file__).resolve().parent / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.template.context_processors.csp",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# capy-project's Content Security Policy (config/settings/security.py), enforced, so a
# page the module renders that the policy would block fails here first. Its report-uri
# is left out: the stand-in project has no view to receive reports.
SECURE_CSP = {
    "default-src": [CSP.NONE],
    "script-src": [CSP.SELF, CSP.NONCE],
    "style-src": [CSP.SELF, CSP.NONCE],
    "img-src": [CSP.SELF, "data:"],
    "font-src": [CSP.SELF],
    "connect-src": [CSP.SELF],
    "object-src": [CSP.NONE],
    "base-uri": [CSP.SELF],
    "form-action": [CSP.SELF],
    "frame-ancestors": [CSP.NONE],
}

USER_MODELS = {"default": "auth.User", "email": "email_users.User"}
TEST_USER_MODEL = os.environ.get("TEST_USER_MODEL", "default")
if TEST_USER_MODEL not in USER_MODELS:
    raise ImproperlyConfigured(
        f"TEST_USER_MODEL must be one of {sorted(USER_MODELS)}, not {TEST_USER_MODEL!r}"
    )
if TEST_USER_MODEL == "email":
    INSTALLED_APPS.append("tests.email_users")
AUTH_USER_MODEL = USER_MODELS[TEST_USER_MODEL]

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite://:memory:")
DATABASES = {"default": dj_database_url.parse(DATABASE_URL)}

USE_TZ = True
STATIC_URL = "static/"
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]  # fast tests
