"""Django system check: without capy-auth's signup form, banned addresses could sign up."""

from django.conf import settings
from django.core.checks import Error
from django.utils.module_loading import import_string

from .forms import BanCheck

SIGNUP_FORM = "capy_auth.bans.forms.BanCheck"


def uses_ban_check():
    path = getattr(settings, "ACCOUNT_SIGNUP_FORM_CLASS", None)
    try:
        form = import_string(path) if path else None
    except ImportError:
        return False
    return isinstance(form, type) and issubclass(form, BanCheck)


def check_signup_form(app_configs, **kwargs):
    if uses_ban_check():
        return []
    return [
        Error(
            "allauth's signup form doesn't check capy-auth's ban list, so banned "
            "addresses could sign up.",
            hint=f'Set ACCOUNT_SIGNUP_FORM_CLASS = "{SIGNUP_FORM}" (a project with its '
            "own signup form makes it a subclass of that class and calls super().clean()).",
            id="capy_auth.E005",
        )
    ]
