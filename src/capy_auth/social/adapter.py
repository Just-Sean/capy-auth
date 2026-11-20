"""capy-auth's social account adapter: allauth asks it which providers exist. It offers
only providers set up in the settings and switched on in the dashboard
(SocialProvider). A project points SOCIALACCOUNT_ADAPTER at it (see the README)."""

from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.socialaccount.models import SocialApp
from django.http import Http404

from .selectors import provider_key, set_up_apps, switched_on


class SocialAccountAdapter(DefaultSocialAccountAdapter):
    def list_apps(self, request, provider=None, client_id=None):
        """Every lookup of a provider's credentials comes here, so a provider that's
        switched off can't be used to sign in, even at its own address."""
        on = switched_on()
        apps = set_up_apps(provider=provider, client_id=client_id)
        return [app for app in apps if provider_key(app) in on]

    def list_providers(self, request):
        """The buttons on the sign-in page: also hides providers without credentials
        (only allauth's pretend one, for development) when they're switched off."""
        on = switched_on()
        return [p for p in super().list_providers(request) if p.sub_id in on]

    def get_provider(self, request, provider, client_id=None):
        """A provider that's switched off (or not set up) is "not found" at its own
        addresses, not a server error."""
        try:
            found = super().get_provider(request, provider, client_id=client_id)
        except SocialApp.DoesNotExist:
            raise Http404 from None  # no switched-on credentials (list_apps)
        if not found.uses_apps and found.id not in switched_on():
            raise Http404  # a provider without credentials (allauth's pretend one)
        return found
