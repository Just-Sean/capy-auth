"""Two-step sign-in is required for staff and superusers (Sean's decision, #30). allauth
has no switch for it, so this middleware does it: a staff member or superuser who hasn't
used two-step sign-in in this session (the second step after the password, a passkey
sign-in, or "Confirm it's you" with it, as allauth records them) is sent from any page
to set it up, or to confirm it's them with it. Meanwhile only the two-step sign-in
pages, "Confirm it's you" and signing out work for them. A project adds it to
MIDDLEWARE (see the README); Django's checks stop the site without it (E010)."""

from allauth.account.authentication import get_authentication_records
from allauth.mfa.models import Authenticator
from allauth.mfa.utils import is_mfa_enabled
from django.contrib import messages
from django.shortcuts import redirect
from django.utils.http import urlencode
from django.utils.translation import gettext_lazy as _

# Pages a staff member can use before two-step sign-in: setting it up and using it
# (allauth's two-step pages), confirming it's them, and signing out.
OPEN_PAGE_PREFIX = "mfa_"
OPEN_PAGES = {"account_reauthenticate", "account_logout"}
SET_UP_PAGE = "mfa_index"
CONFIRM_WITH_CODE = "mfa_reauthenticate"
CONFIRM_WITH_PASSKEY = "mfa_reauthenticate_webauthn"
SET_UP_MESSAGE = _("Staff accounts need two-step sign-in. Set it up to continue.")
CONFIRM_MESSAGE = _("Staff accounts need two-step sign-in. Confirm it’s you to continue.")


def needs_two_step(user):
    return user.is_authenticated and (user.is_staff or user.is_superuser)


def used_two_step(request):
    records = get_authentication_records(request, request.user)
    return any(record.get("method") == "mfa" for record in records)


def is_open_page(match):
    if match.namespaces:  # the admin and other apps' namespaced pages
        return False
    name = match.url_name or ""
    return name.startswith(OPEN_PAGE_PREFIX) or name in OPEN_PAGES


def confirm_page(user):
    """The code page when the person has an authenticator app (it also takes a
    recovery code), the passkey page when they only have passkeys."""
    has_app = Authenticator.objects.filter(user=user, type=Authenticator.Type.TOTP).exists()
    return CONFIRM_WITH_CODE if has_app else CONFIRM_WITH_PASSKEY


class StaffTwoStepMiddleware:
    """Runs before each view (process_view, where the page's name is known)."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_view(self, request, view_func, view_args, view_kwargs):
        user = request.user
        if not needs_two_step(user) or is_open_page(request.resolver_match):
            return None
        if not is_mfa_enabled(user):
            messages.info(request, SET_UP_MESSAGE)
            return redirect(SET_UP_PAGE)
        if used_two_step(request):
            return None
        messages.info(request, CONFIRM_MESSAGE)
        response = redirect(confirm_page(user))
        response["Location"] += "?" + urlencode({"next": request.get_full_path()})
        return response
