"""Two-step sign-in is required for staff and superusers (Sean's decision, #30). allauth
has no switch for it, so this middleware does it. A staff member or superuser is "due"
until they have used two-step sign-in in this session: the second step after the
password, a passkey sign-in, "Confirm it's you" with it (as allauth records them), or
setting it up (capy-auth records that, since allauth doesn't count it as a sign-in).

What a due person can open depends on why they're due, so a password alone never gets
them past it:
- no two-step sign-in yet ("set_up"): setting up an app or a passkey, confirming it's
  them first as those pages ask (password or emailed code), and signing out;
- two-step sign-in set up but not used in this session ("confirm"): only confirming
  with it, and signing out. Not the recovery codes or managing authenticators, which a
  password would open.

A project adds it to MIDDLEWARE after allauth's (see the README); Django's checks stop
the site without it (E010)."""

from allauth.account.authentication import get_authentication_records
from allauth.mfa.models import Authenticator
from allauth.mfa.utils import is_mfa_enabled
from django.shortcuts import redirect
from django.utils.http import url_has_allowed_host_and_scheme, urlencode

SET_UP = "set_up"
CONFIRM = "confirm"
SIGN_OUT_PAGES = {"account_logout", "admin:logout"}
OPEN_PAGES = {
    SET_UP: SIGN_OUT_PAGES
    | {
        "mfa_index",
        "mfa_activate_totp",
        "mfa_add_webauthn",
        "account_reauthenticate",
        "account_request_reauthentication_code",
        "account_confirm_reauthentication_code",
    },
    CONFIRM: SIGN_OUT_PAGES | {"mfa_reauthenticate", "mfa_reauthenticate_webauthn"},
}
SET_UP_PAGE = "mfa_index"
CONFIRM_WITH_CODE = "mfa_reauthenticate"
CONFIRM_WITH_PASSKEY = "mfa_reauthenticate_webauthn"
# Set on the request for the pages and the account adapter: SET_UP, CONFIRM or None.
REQUEST_ATTRIBUTE = "capy_auth_two_step_due"
# Where a person sent to set it up was going, for the "Continue" button afterwards; kept
# until they leave the pages that follow setting it up.
NEXT_SESSION_KEY = "capy_auth_staff_next"
AFTER_SET_UP_PAGES = OPEN_PAGES[SET_UP] | {
    "mfa_view_recovery_codes",
    "mfa_download_recovery_codes",
    "mfa_list_webauthn",
}
# Setting it up proves the person has it; allauth records it only as an addition.
SET_UP_SESSION_KEY = "capy_auth_two_step_set_up_by"


def needs_two_step(user):
    return user.is_authenticated and (user.is_staff or user.is_superuser)


def used_two_step(request):
    user = request.user
    if request.session.get(SET_UP_SESSION_KEY) == str(user.pk):
        return True
    records = get_authentication_records(request, user)
    return any(record.get("method") == "mfa" for record in records)


def two_step_due(request):
    user = request.user
    if not needs_two_step(user):
        return None
    if not is_mfa_enabled(user):
        return SET_UP
    return None if used_two_step(request) else CONFIRM


def confirm_page(user):
    """The code page when the person has an authenticator app (it also takes a
    recovery code), the passkey page when they only have passkeys."""
    has_app = is_mfa_enabled(user, [Authenticator.Type.TOTP])
    return CONFIRM_WITH_CODE if has_app else CONFIRM_WITH_PASSKEY


def remember_destination(request):
    """Only a path on this site (a request for "//other.example/" isn't one)."""
    path = request.get_full_path()
    if url_has_allowed_host_and_scheme(path, allowed_hosts=None):
        request.session[NEXT_SESSION_KEY] = path


def remember_set_up(sender, request, user, **kwargs):
    """allauth's authenticator_added signal: the person just set up an app or a passkey
    (typing its code, or answering with the key), so this session has used it."""
    if request is not None and request.user.pk == user.pk:
        request.session[SET_UP_SESSION_KEY] = str(user.pk)


class StaffTwoStepMiddleware:
    """Runs before each view (process_view, where the page's name is known)."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_view(self, request, view_func, view_args, view_kwargs):
        due = two_step_due(request)
        setattr(request, REQUEST_ATTRIBUTE, due)
        page = request.resolver_match.view_name
        if due is None:
            if page not in AFTER_SET_UP_PAGES:
                request.session.pop(NEXT_SESSION_KEY, None)
            return None
        if page in OPEN_PAGES[due]:
            return None
        if due == SET_UP:
            remember_destination(request)
            return redirect(SET_UP_PAGE)
        response = redirect(confirm_page(request.user))
        response["Location"] += "?" + urlencode({"next": request.get_full_path()})
        return response
