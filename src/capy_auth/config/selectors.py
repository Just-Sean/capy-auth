"""Reads capy-auth's settings record, creating it the first time it's needed."""

from django.conf import settings

from .models import AuthSettings, BreachedPasswordCheck


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
    """The settings record; created from starting_values() the first time it's read."""
    record, _created = AuthSettings.objects.get_or_create(
        pk=AuthSettings.SINGLETON_ID, defaults=starting_values()
    )
    return record
