"""Django system checks (run by `manage.py check`, `migrate` and `runserver`) for mistakes
that would make the capy-auth settings page quietly do nothing or crash."""

from allauth.account import app_settings as account_settings
from django.conf import settings
from django.core.checks import Error
from django.utils.module_loading import import_string

from capy_auth.account.adapter import AccountAdapter

ADAPTER_PATH = "capy_auth.account.adapter.AccountAdapter"


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
    """The CAPY_AUTH_ starting values must be True or False: a string such as "false"
    from the environment would make the signup and settings pages fail."""
    value = getattr(settings, "CAPY_AUTH_SIGNUP_OPEN", True)
    if isinstance(value, bool):
        return []
    return [
        Error(
            f"CAPY_AUTH_SIGNUP_OPEN must be True or False, not {value!r}.",
            hint="When it comes from the environment, read it as a true/false value "
            '(e.g. env.bool("CAPY_AUTH_SIGNUP_OPEN", default=True)).',
            id="capy_auth.E002",
        )
    ]
