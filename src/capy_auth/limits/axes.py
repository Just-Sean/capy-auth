"""django-axes (capy-project's login lockouts) counts failed logins per name and address.
allauth logs in by email and axes by username, so without this every failed email login
from one address would count under one empty name, and five of them would lock out
everyone behind that address. A project points AXES_USERNAME_CALLABLE here."""

from allauth.account.models import EmailAddress
from django.contrib.auth import get_user_model


def login_name(request, credentials):
    """The name axes counts a login under: the account's main email, in lowercase,
    whichever of the account's addresses was typed (allauth's pages), by username (the
    admin's own login page), or as axes' own reset after a successful login (also by
    username). So every way into one account counts together. Without an account, the
    name as typed, in lowercase."""
    credentials = credentials or {}
    if credentials.get("email") is not None:
        return email_name(credentials["email"])
    if credentials.get("username"):
        return username_name(credentials["username"])
    data = getattr(request, "POST", {}) if request is not None else {}
    if data.get("login") or data.get("email"):
        return email_name(data.get("login") or data.get("email"))
    if data.get("username"):
        return username_name(data["username"])
    return None


def email_name(typed):
    typed = typed.strip().lower()
    address = EmailAddress.objects.filter(email=typed).select_related("user").first()
    return main_email(address.user) if address else typed


def username_name(typed):
    users = get_user_model()
    try:
        user = users._default_manager.get_by_natural_key(typed)
    except users.DoesNotExist:
        return typed.strip().lower()
    return main_email(user) or typed.strip().lower()


def main_email(user):
    email = getattr(user, get_user_model().get_email_field_name(), "") or ""
    return email.strip().lower() or None
