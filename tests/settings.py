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
from datetime import timedelta
from pathlib import Path

import dj_database_url
from cryptography.fernet import Fernet
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
    "allauth.usersessions",
    "allauth.mfa",
    "axes",
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
    "allauth.usersessions.middleware.UserSessionsMiddleware",
    "capy_auth.limits.middleware.CacheDownMiddleware",
    "capy_auth.mfa.staff.StaffTwoStepMiddleware",
    "axes.middleware.AxesMiddleware",  # last, as in capy-project
]

# As the README tells a project: django-axes first (lockouts, as capy-project runs
# them; capy-project's own per-address limit is its own code, so not here), then
# allauth's backend for every sign-in, the admin's included (tests/urls.py).
AUTHENTICATION_BACKENDS = [
    "axes.backends.AxesStandaloneBackend",
    "allauth.account.auth_backends.AuthenticationBackend",
]
# capy-project's django-axes settings (config/settings/users.py; its client_ip copied
# small in tests/client_ip.py), plus capy-auth's two lines.
BEHIND_PROXY = False  # capy-project's setting; tests switch it on
AXES_FAILURE_LIMIT = 5
AXES_COOLOFF_TIME = timedelta(minutes=15)
AXES_LOCKOUT_PARAMETERS = [["username", "ip_address"]]
AXES_RESET_ON_SUCCESS = True
AXES_ENABLE_RETRY_AFTER_HEADER = True
AXES_CLIENT_IP_CALLABLE = "tests.client_ip.client_ip"
AXES_DISABLE_ACCESS_LOG = True
AXES_SENSITIVE_PARAMETERS = ["username", "ip_address"]
AXES_VERBOSE = False
AXES_USERNAME_CALLABLE = "capy_auth.limits.axes.login_name"
AXES_LOCKOUT_TEMPLATE = "capy_auth/locked_out.html"

# capy-auth's allauth settings, exactly as the README's "Add it to a project" gives them.
ACCOUNT_ADAPTER = "capy_auth.account.adapter.AccountAdapter"
ACCOUNT_LOGIN_METHODS = {"email"}
ACCOUNT_SIGNUP_FIELDS = ["email*", "password1*", "password2*"]
ACCOUNT_EMAIL_VERIFICATION = "mandatory"
ACCOUNT_EMAIL_VERIFICATION_BY_CODE_ENABLED = True
ACCOUNT_EMAIL_VERIFICATION_SUPPORTS_RESEND = True
ACCOUNT_SESSION_REMEMBER = True
ACCOUNT_EMAIL_NOTIFICATIONS = True
ACCOUNT_REAUTHENTICATION_REQUIRED = True
ACCOUNT_USER_DISPLAY = "capy_auth.account.adapter.user_display"
ACCOUNT_SIGNUP_FORM_CLASS = "capy_auth.bans.forms.BanCheck"
PASSWORD_RESET_TIMEOUT = 60 * 60  # reset links work for 1 hour
# Not behind a proxy here; projects behind one set 1 (README).
ALLAUTH_TRUSTED_PROXY_COUNT = 0

# MFA, as the README tells a project: authenticator apps, passkeys and security keys, and
# recovery codes, secrets encrypted by capy-auth's adapter with a key made each run
# (nothing to keep secret). MFA_WEBAUTHN_ALLOW_INSECURE_ORIGIN stays off: the test
# authenticator signs for https://testserver, so the origin check really runs.
MFA_ADAPTER = "capy_auth.mfa.adapter.MFAAdapter"
MFA_FORMS = {
    "add_webauthn": "capy_auth.mfa.forms.AddPasskeyForm",
    "edit_webauthn": "capy_auth.mfa.forms.EditPasskeyForm",
}
MFA_SUPPORTED_TYPES = ["totp", "recovery_codes", "webauthn"]
MFA_PASSKEY_LOGIN_ENABLED = True  # "Sign in with a passkey"; signing up with one stays off
MFA_TOTP_TOLERANCE = 1  # the previous 30-second code still works (RFC 6238)
CAPY_AUTH_ENCRYPTION_KEYS = [Fernet.generate_key().decode()]

# capy-project's password rules (config/settings/users.py).
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 12},
    },
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
    # capy-auth's breached-password check, as the README tells projects to add it.
    {"NAME": "capy_auth.passwords.breached.BreachedPasswordValidator"},
]

# Email, kept in memory (Django's test runner also collects it in mail.outbox).
MAILERS = {"default": {"BACKEND": "django.core.mail.backends.locmem.EmailBackend"}}
DEFAULT_FROM_EMAIL = "accounts@example.com"

# Background jobs run straight away, as in capy-project's development and tests.
TASKS = {"default": {"BACKEND": "django.tasks.backends.immediate.ImmediateBackend"}}

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
