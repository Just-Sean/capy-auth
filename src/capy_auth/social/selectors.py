"""Reading the providers: which are set up in the settings, and which are switched on.
Only the settings count: allauth's database-stored apps (SocialApp) would keep the
client secret in the database, so capy-auth never reads them (nor queries their table)."""

from allauth.core import context
from allauth.socialaccount.adapter import _build_apps_from_settings

from .models import SocialProvider

REQUEST_ATTRIBUTE = "_capy_auth_providers_on"


def provider_key(app):
    """The id the Sign-in providers page knows a provider by: an OpenID Connect server's own
    provider_id, or allauth's id for the provider."""
    return app.provider_id or app.provider


def set_up_apps(provider=None, client_id=None):
    """The apps in SOCIALACCOUNT_PROVIDERS, built by allauth's own code for that (no
    database; a test fails if an allauth upgrade changes it)."""
    by_provider = _build_apps_from_settings(provider=provider, client_id=client_id)
    return [app for apps in by_provider.values() for app in apps]


def switched_on():
    """The ids switched on on the Sign-in providers page. Read once per request (kept on the request
    allauth's middleware holds), since a page asks once per provider."""
    request = context.request
    ids = getattr(request, REQUEST_ATTRIBUTE, None)
    if ids is None:
        ids = set(SocialProvider.objects.filter(enabled=True).values_list("provider_id", flat=True))
        if request is not None:
            setattr(request, REQUEST_ATTRIBUTE, ids)
    return ids
