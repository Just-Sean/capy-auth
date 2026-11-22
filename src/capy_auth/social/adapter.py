"""capy-auth's social account adapter: allauth asks it which providers exist. It reads
providers only from the settings (never the database), offers only those switched on on
the admin's Sign-in providers page, and refuses a sign-in or a new connection through a
switched-off one. Looking up the provider of an account already connected still works,
so people can see and remove it. A project points SOCIALACCOUNT_ADAPTER at it (see the
README)."""

from allauth.core.exceptions import ImmediateHttpResponse
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.socialaccount.helpers import render_authentication_error
from allauth.socialaccount.models import SocialApp
from allauth.socialaccount.providers.base.constants import AuthError, AuthProcess
from django.conf import settings
from django.core.exceptions import MultipleObjectsReturned
from django.http import Http404, HttpResponseNotFound

from capy_auth.bans.models import AttemptKind
from capy_auth.bans.selectors import is_banned_email, is_banned_social_account
from capy_auth.bans.services import record_attempt

from .selectors import is_pretend, set_up_apps, switched_on

# The ends of allauth's names for a provider's own addresses: starting a sign-in
# (github_login, openid_connect_login), coming back (…_callback), and the pretend
# provider's form (dummy_authenticate).
SIGN_IN_ADDRESS_ENDINGS = ("_login", "_callback", "_authenticate")
# allauth's sign-in API's addresses for the same.
API_SIGN_IN_ADDRESSES = {"redirect_to_provider", "provider_token"}


def is_sign_in_address(request):
    match = getattr(request, "resolver_match", None)
    name = (match.url_name or "") if match else ""
    if name in API_SIGN_IN_ADDRESSES:
        return True
    return name.endswith(SIGN_IN_ADDRESS_ENDINGS) and not name.startswith("account_")


def emails_from_provider(sociallogin):
    """The emails the provider gave: its list, and the one on the new account allauth
    built from its answer (an existing account's own email isn't the provider's)."""
    emails = {address.email for address in sociallogin.email_addresses}
    if not sociallogin.is_existing and sociallogin.user is not None and sociallogin.user.email:
        emails.add(sociallogin.user.email)
    return emails


def record_banned_emails(request, sociallogin, emails):
    """For staff, like a banned signup or added address: a connection is recorded
    against the signed-in account; an existing account signing in isn't recorded."""
    if sociallogin.state.get("process") == AuthProcess.CONNECT:
        for email in emails:
            record_attempt(email, AttemptKind.ADD_EMAIL, request, account=request.user)
    elif not sociallogin.is_existing:
        for email in emails:
            record_attempt(email, AttemptKind.SIGNUP, request)


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
        provider has answered: refused when it's switched off, or when the account at
        the provider or any email it gives is on the ban list (the page doesn't say
        why, as at email signup; a new account's banned email is recorded for staff)."""
        account = sociallogin.account
        if account.provider not in switched_on():
            raise ImmediateHttpResponse(HttpResponseNotFound())
        banned_emails = [e for e in emails_from_provider(sociallogin) if is_banned_email(e)]
        record_banned_emails(request, sociallogin, banned_emails)
        if banned_emails or is_banned_social_account(account.provider, account.uid):
            error_page = render_authentication_error(
                request,
                account.get_provider(),
                AuthError.DENIED,
                extra_context={"state": sociallogin.state},  # for allauth's API clients
            )
            raise ImmediateHttpResponse(error_page)
        super().pre_social_login(request, sociallogin)

    def can_authenticate_by_email(self, login, email):
        """Never join a provider to an existing account just because the emails match
        (Sean's decision): not even when a project's per-provider settings ask for it.
        The person signs in to the account first, then connects the provider."""
        return False
