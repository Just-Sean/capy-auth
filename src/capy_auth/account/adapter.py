"""capy-auth's account adapter: allauth asks it how to behave. A project points
ACCOUNT_ADAPTER at it (see the README)."""

import secrets

from allauth.account.adapter import DefaultAccountAdapter
from allauth.core import context
from django.contrib import messages
from django.contrib.auth.hashers import make_password
from django.contrib.sites.shortcuts import get_current_site
from django.utils.translation import gettext_lazy as _

from capy_auth.bans.models import AttemptKind
from capy_auth.bans.selectors import is_banned_email
from capy_auth.bans.services import BANNED_ADDRESS_NOTICE, NOTICES, record_attempt
from capy_auth.config.selectors import get_auth_settings
from capy_auth.emails.tasks import queue_email


def user_display(user):
    """How allauth names a person in messages and emails: their email address, which
    they chose, not the username allauth made up for them (ACCOUNT_USER_DISPLAY)."""
    return user.email or user.get_username()


EMAIL_NOT_CONFIRMED = _("This email address couldn’t be confirmed.")
# The "Other ways to confirm it's you" links, in the words capy-auth's pages use.
REAUTHENTICATION_LINKS = {
    "mfa_reauthenticate": _("Use your authenticator app or a recovery code"),
    "mfa_reauthenticate:webauthn": _("Use a passkey or security key"),
}


class AccountAdapter(DefaultAccountAdapter):
    error_messages = {
        **DefaultAccountAdapter.error_messages,
        # allauth shows this both for too many failed logins and when a code has been
        # mistyped too often, so it covers both.
        "too_many_login_attempts": _(
            "Too many attempts. If you were entering a code, it can’t be used any more: "
            "sign in again to get a new one. Otherwise, please wait a few minutes, then "
            "try again."
        ),
    }

    def is_open_for_signup(self, request):
        """Open only when allauth's own setting allows it and admins haven't closed
        signup on the capy-auth settings page."""
        return super().is_open_for_signup(request) and get_auth_settings().signup_open

    def send_account_already_exists_mail(self, email):
        """Signing up with a taken email sends this instead of creating an account. A
        new account's password is hashed, which takes time, so hash one here too:
        otherwise the faster answer would show the email already has an account. A banned
        address comes here too (capy_auth.bans.forms), and is recorded for staff; the
        email itself becomes the ban notice (send_mail)."""
        make_password(secrets.token_urlsafe())
        if is_banned_email(email):
            record_attempt(email, AttemptKind.SIGNUP, context.request)
        super().send_account_already_exists_mail(email)

    def confirm_email(self, request, email_address):
        """A banned address is never confirmed, so it can't be added to an account. The
        message doesn't say why (allauth's own says another account has it)."""
        if is_banned_email(email_address.email):
            self.add_message(request, messages.ERROR, message=EMAIL_NOT_CONFIRMED)
            return False
        return super().confirm_email(request, email_address)

    def get_reauthentication_methods(self, user):
        """allauth's ways to confirm it's you, worded like capy-auth's pages."""
        methods = super().get_reauthentication_methods(user)
        for method in methods:
            method["description"] = REAUTHENTICATION_LINKS.get(method["id"], method["description"])
        return methods

    def send_mail(self, template_prefix, email, context_data):
        """Builds the email as allauth does, then has the background worker send it
        (capy_auth/emails/). A banned address only ever gets the ban notice (or, for a
        suspended account, the suspension notice): never a code or a link."""
        if template_prefix not in NOTICES and is_banned_email(email):
            template_prefix, context_data = BANNED_ADDRESS_NOTICE, {}
        request = context.request
        mail_context = {
            "request": request,
            "email": email,
            "current_site": get_current_site(request),
            **context_data,
        }
        queue_email(self.render_mail(template_prefix, email, mail_context))
