"""Reads capy-auth's settings record, creating it the first time it's needed."""

from django.conf import settings

from .models import AuthSettings


def starting_values():
    """The values a new settings record starts with, from the project's settings. After
    that, what admins set on the dashboard wins."""
    return {"signup_open": getattr(settings, "CAPY_AUTH_SIGNUP_OPEN", True)}


def get_auth_settings():
    record, _created = AuthSettings.objects.get_or_create(
        pk=AuthSettings.SINGLETON_ID, defaults=starting_values()
    )
    return record
