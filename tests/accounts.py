"""Shared by the tests that sign people up, log them in and reset passwords."""

import re
import secrets

from django.contrib.auth import get_user_model
from django.urls import reverse

PASSWORD = secrets.token_urlsafe()  # made each run, so no password is written here
NEW_PASSWORD = secrets.token_urlsafe()
SIGNUP = reverse("account_signup")
LOGIN = reverse("account_login")
LOGOUT = reverse("account_logout")
ACCOUNT_PAGE = reverse("capy_auth_account")
RESET = reverse("account_reset_password")
CHANGE_PASSWORD = reverse("account_change_password")


def users_with_email(email):
    return get_user_model().objects.filter(email__iexact=email)


def code_from(message):
    """The verification code in an email (allauth's: letters and digits, with a dash)."""
    return re.search(r"^\s*([A-Z0-9]{4}-[A-Z0-9]{4})\s*$", message.body, re.MULTILINE).group(1)


def sign_up(client, email="eve@example.com", password=PASSWORD):
    return client.post(SIGNUP, {"email": email, "password1": password, "password2": password})


def log_in(client, email="ada@example.com", password=PASSWORD):
    return client.post(LOGIN, {"login": email, "password": password})


def reset_link(message):
    """The path of the password reset link in an email."""
    link = re.search(r"https?://testserver(/accounts/password/reset/key/\S+/)", message.body)
    return link.group(1)
