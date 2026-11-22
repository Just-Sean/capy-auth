"""Reads capy-auth's settings record, creating it the first time it's needed."""

from allauth.core import context
from django.conf import settings

from .models import AuthSettings, BreachedPasswordCheck

REQUEST_ATTRIBUTE = "_capy_auth_settings"


def starting_values():
    """The values a new settings record starts with, from the project's settings. After
    that, what admins set on the capy-auth settings page wins. (An option added in a
    later release gets the project's setting copied into the existing record by its
    migration: see the README's Settings section.)"""
    return {
        "signup_open": getattr(settings, "CAPY_AUTH_SIGNUP_OPEN", True),
        "breached_password_check": getattr(
            settings, "CAPY_AUTH_BREACHED_PASSWORD_CHECK", BreachedPasswordCheck.EVERYONE
        ),
    }


def get_auth_settings():
    """The settings record; created from starting_values() the first time it's read.
    Read once per request: allauth's middleware keeps the current request, and the
    record is kept on it, so a page that asks several times (the password help text is
    built more than once) still makes one query."""
    request = context.request
    record = getattr(request, REQUEST_ATTRIBUTE, None)
    if record is None:
        record, _created = AuthSettings.objects.get_or_create(
            pk=AuthSettings.SINGLETON_ID, defaults=starting_values()
        )
        if request is not None:
            setattr(request, REQUEST_ATTRIBUTE, record)
    return record
