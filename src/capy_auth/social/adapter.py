"""capy-auth's social account adapter: allauth asks it which providers exist. It reads
providers only from the settings (never the database), offers only those switched on on
the admin's Sign-in providers page, and refuses a sign-in or a new connection through a
switched-off one. Looking up the provider of an account already connected still works,
so people can see and remove it. A project points SOCIALACCOUNT_ADAPTER at it (see the
README)."""

from allauth.core.exceptions import ImmediateHttpResponse
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.socialaccount.models import SocialApp
from django.conf import settings
from django.core.exceptions import MultipleObjectsReturned
from django.http import Http404, HttpResponseNotFound

from .selectors import is_pretend, set_up_apps, switched_on

# The ends of allauth's names for a provider's own addresses: starting a sign-in
# (github_login, openid_connect_login), coming back (…_callback), and the pretend
# provider's form (dummy_authenticate).
SIGN_IN_ADDRESS_ENDINGS = ("_login", "_callback", "_authenticate")


def is_sign_in_address(request):
    match = getattr(request, "resolver_match", None)
    name = (match.url_name or "") if match else ""
    return name.endswith(SIGN_IN_ADDRESS_ENDINGS) and not name.startswith("account_")


class SocialAccountAdapter(DefaultSocialAccountAdapter):
    def list_apps(self, request, provider=None, client_id=None):
        return set_up_apps(provider=provider, client_id=client_id)

    def list_providers(self, request):
        """The buttons on the sign-in page: only switched-on providers."""
        on = switched_on()
        return [p for p in super().list_providers(request) if p.sub_id in on]

    def get_provider(self, request, provider, client_id=None):
        """A provider that isn't set up is "not found" at its addresses, not a server
        error; so is a switched-off one at the addresses that start or finish a sign-in
        (other lookups, such as an account already connected, still find it). allauth's
        pretend provider is refused outright with DEBUG off."""
        try:
            found = super().get_provider(request, provider, client_id=client_id)
        except SocialApp.DoesNotExist, MultipleObjectsReturned:
            raise Http404 from None
        if is_pretend(found) and not settings.DEBUG:
            raise Http404  # E014 stops the site too, but only when checks run
        if is_sign_in_address(request) and found.sub_id not in switched_on():
            raise Http404
        return found

    def pre_social_login(self, request, sociallogin):
        """Every sign-in and new connection through a provider comes here once the
        provider has answered: refused when it's switched off."""
        if sociallogin.account.provider not in switched_on():
            raise ImmediateHttpResponse(HttpResponseNotFound())
        super().pre_social_login(request, sociallogin)
