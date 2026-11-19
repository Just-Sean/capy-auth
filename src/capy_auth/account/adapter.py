"""capy-auth's account adapter: allauth asks it how to behave. A project points
ACCOUNT_ADAPTER at it (see the README)."""

import secrets

from allauth.account.adapter import DefaultAccountAdapter
from django.contrib.auth.hashers import make_password
from django.utils.translation import gettext_lazy as _

from capy_auth.config.selectors import get_auth_settings


def user_display(user):
    """How allauth names a person in messages and emails: their email address, which
    they chose, not the username allauth made up for them (ACCOUNT_USER_DISPLAY)."""
    return user.email or user.get_username()


class AccountAdapter(DefaultAccountAdapter):
    error_messages = {
        **DefaultAccountAdapter.error_messages,
        # allauth shows this both for too many failed logins and when a code has been
        # mistyped too often, so it covers both.
        "too_many_login_attempts": _(
            "Too many attempts. If you were entering a code, it can't be used any more: "
            "sign in again to get a new one. Otherwise, try again in a few minutes."
        ),
    }

    def is_open_for_signup(self, request):
        """Open only when allauth's own setting allows it and admins haven't closed
        signup on the capy-auth settings page."""
        return super().is_open_for_signup(request) and get_auth_settings().signup_open

    def send_account_already_exists_mail(self, email):
        """Signing up with a taken email sends this instead of creating an account. A
        new account's password is hashed, which takes time, so hash one here too:
        otherwise the faster answer would show the email already has an account."""
        make_password(secrets.token_urlsafe())
        super().send_account_already_exists_mail(email)
