"""Django system checks (run by `manage.py check`, `migrate` and `runserver`) for mistakes
in a project's setup: errors for what would make the capy-auth settings page quietly do
nothing or crash, warnings for allauth settings that weaken capy-auth's security choices
(the README's install step 4)."""

from allauth import app_settings as allauth_settings
from allauth.account import app_settings as account_settings
from django.conf import settings
from django.core.checks import Error, Warning
from django.utils.module_loading import import_string

from capy_auth.account.adapter import AccountAdapter
from capy_auth.config.models import BreachedPasswordCheck
from capy_auth.config.selectors import starting_values

ADAPTER_PATH = "capy_auth.account.adapter.AccountAdapter"
MAX_RESET_LINK_SECONDS = 60 * 60
# How long allauth trusts a re-entered password before asking again (its default).
MAX_REAUTHENTICATION_SECONDS = 300
BREACHED_VALIDATOR = "capy_auth.passwords.breached.BreachedPasswordValidator"
JOBS_RUN_AT_ONCE = "django.tasks.backends.immediate.ImmediateBackend"
# Caches the web process and a separate worker share, kept in memory (not on disk).
SHARED_CACHES = {
    "django.core.cache.backends.redis.RedisCache",
    "django.core.cache.backends.memcached.PyMemcacheCache",
    "django.core.cache.backends.memcached.PyLibMCCache",
}


def check_account_adapter(app_configs, **kwargs):
    """allauth must use capy-auth's adapter (or a subclass), or the settings page's
    choices, such as closing signup, have no effect."""
    if issubclass(import_string(account_settings.ADAPTER), AccountAdapter):
        return []
    return [
        Error(
            "allauth isn't using capy-auth's account adapter, so the capy-auth settings "
            "page has no effect (closing signup wouldn't close it).",
            hint=f'Set ACCOUNT_ADAPTER = "{ADAPTER_PATH}", or make the project\'s own '
            "adapter a subclass of it.",
            id="capy_auth.E001",
        )
    ]


def check_starting_values(app_configs, **kwargs):
    """The CAPY_AUTH_ starting values must be ones the settings record accepts: a string
    such as "false" from the environment would make the signup and settings pages fail."""
    values = starting_values()
    errors = []
    if not isinstance(values["signup_open"], bool):
        errors.append(
            Error(
                f"CAPY_AUTH_SIGNUP_OPEN must be True or False, not {values['signup_open']!r}.",
                hint="When it comes from the environment, read it as a true/false value "
                '(e.g. env.bool("CAPY_AUTH_SIGNUP_OPEN", default=True)).',
                id="capy_auth.E002",
            )
        )
    if values["breached_password_check"] not in BreachedPasswordCheck.values:
        errors.append(
            Error(
                f"CAPY_AUTH_BREACHED_PASSWORD_CHECK must be one of "
                f"{', '.join(BreachedPasswordCheck.values)}, "
                f"not {values['breached_password_check']!r}.",
                hint="When it comes from the environment, read it as text "
                '(e.g. env.str("CAPY_AUTH_BREACHED_PASSWORD_CHECK", default="everyone")).',
                id="capy_auth.E003",
            )
        )
    return errors


def check_breached_password_validator(app_configs, **kwargs):
    """Without capy-auth's validator in the project's password rules, the settings
    page's "check breached passwords" option does nothing."""
    names = {validator.get("NAME") for validator in settings.AUTH_PASSWORD_VALIDATORS}
    if BREACHED_VALIDATOR in names:
        return []
    return [
        Warning(
            "capy-auth's breached-password check isn't in AUTH_PASSWORD_VALIDATORS, so the "
            'capy-auth settings page\'s "check breached passwords" option has no effect.',
            hint=f'Add {{"NAME": "{BREACHED_VALIDATOR}"}} to AUTH_PASSWORD_VALIDATORS.',
            id="capy_auth.W003",
        )
    ]


def security_settings():
    """(setting, what capy-auth expects, whether the project has it) for each security
    choice the README's install step 4 makes."""
    behind_proxy = bool(getattr(settings, "SECURE_PROXY_SSL_HEADER", None))
    return [
        ("ACCOUNT_LOGIN_METHODS", '{"email"}', account_settings.LOGIN_METHODS == {"email"}),
        (
            "ACCOUNT_EMAIL_VERIFICATION",
            '"mandatory"',
            account_settings.EMAIL_VERIFICATION
            == account_settings.EmailVerificationMethod.MANDATORY,
        ),
        (
            "ACCOUNT_EMAIL_VERIFICATION_BY_CODE_ENABLED",
            "True",
            account_settings.EMAIL_VERIFICATION_BY_CODE_ENABLED,
        ),
        ("ACCOUNT_PREVENT_ENUMERATION", "True", bool(account_settings.PREVENT_ENUMERATION)),
        ("ACCOUNT_REAUTHENTICATION_REQUIRED", "True", account_settings.REAUTHENTICATION_REQUIRED),
        (
            "ACCOUNT_REAUTHENTICATION_TIMEOUT",
            f"at most {MAX_REAUTHENTICATION_SECONDS} (5 minutes)",
            account_settings.REAUTHENTICATION_TIMEOUT <= MAX_REAUTHENTICATION_SECONDS,
        ),
        (
            "PASSWORD_RESET_TIMEOUT",
            f"at most {MAX_RESET_LINK_SECONDS} (1 hour)",
            settings.PASSWORD_RESET_TIMEOUT <= MAX_RESET_LINK_SECONDS,
        ),
        (
            "ALLAUTH_TRUSTED_PROXY_COUNT",
            "1 behind a proxy (SECURE_PROXY_SSL_HEADER is set)",
            not behind_proxy
            or allauth_settings.TRUSTED_PROXY_COUNT > 0
            or bool(allauth_settings.TRUSTED_CLIENT_IP_HEADER),
        ),
    ]


def check_security_settings(app_configs, **kwargs):
    return [
        Warning(
            f"{name} should be {expected} for capy-auth's security choices.",
            hint='See capy-auth\'s README, "Add it to a project", step 4.',
            id="capy_auth.W001",
        )
        for name, expected, ok in security_settings()
        if not ok
    ]


def check_email_queue(app_configs, **kwargs):
    """capy-auth's emails wait in the cache for the worker: with jobs run by a separate
    worker, a cache only one process sees (or one on disk, or none) loses or stores them
    (capy_auth/emails/)."""
    task_backend = settings.TASKS.get("default", {}).get("BACKEND")
    cache_backend = settings.CACHES["default"]["BACKEND"]
    if task_backend == JOBS_RUN_AT_ONCE or cache_backend in SHARED_CACHES:
        return []
    return [
        Warning(
            f"capy-auth's emails wait in the cache for the background worker, but the "
            f"default cache ({cache_backend}) isn't one the worker shares and keeps in "
            f"memory, so emails could be lost or written to disk.",
            hint="Use Redis (as capy-project does) or Memcached for the default cache.",
            id="capy_auth.W002",
        )
    ]
