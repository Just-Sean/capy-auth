"""Keeping the Sign-in providers page's list in step with the providers set up in the settings."""

from allauth.socialaccount.providers import registry
from django.apps import apps as global_apps
from django.conf import settings
from django.db import DEFAULT_DB_ALIAS

from .selectors import provider_key, set_up_apps

STARTING_SETTING = "CAPY_AUTH_SOCIAL_PROVIDERS_ON"


def set_up_providers():
    """{id: name} of the providers with credentials in the settings (an OpenID Connect
    server by its own name), and allauth's pretend provider (which has none) when it's
    installed."""
    found = {
        provider_key(app): app.name or getattr(registry.get_class(app.provider), "name", "")
        for app in set_up_apps()
    }
    found.update({cls.id: cls.name for cls in registry.get_class_list() if not cls.uses_apps})
    return found


def set_up_provider_ids():
    return set(set_up_providers())


def starting_ids():
    """CAPY_AUTH_SOCIAL_PROVIDERS_ON, when it's a list of ids (E015 reports otherwise)."""
    value = getattr(settings, STARTING_SETTING, [])
    return set(value) if isinstance(value, list | tuple) else set()


def add_new_providers(apps=global_apps, using=DEFAULT_DB_ALIAS, **kwargs):
    """After each migrate (as every deploy runs): a row for each newly set-up provider,
    switched on if CAPY_AUTH_SOCIAL_PROVIDERS_ON lists it. Existing rows keep the
    page's choice; rows for providers no longer set up stay, marked in the admin.
    Uses the table as the migrations left it (Django's post_migrate `apps`), so a
    migrate back to before it existed does nothing."""
    try:
        provider_model = apps.get_model("capy_auth", "SocialProvider")
    except LookupError:
        return
    start_on = starting_ids()
    for provider_id in set_up_provider_ids():
        provider_model.objects.using(using).get_or_create(
            provider_id=provider_id, defaults={"enabled": provider_id in start_on}
        )
