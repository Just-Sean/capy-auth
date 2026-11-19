"""django-axes (capy-project's login lockouts) counts failed logins per name and address.
allauth logs in by email and axes by username, so without this every failed email login
from one address would count under one empty name, and five of them would lock out
everyone behind that address. A project points AXES_USERNAME_CALLABLE here."""

from django.contrib.auth import get_user_model


def login_name(request, credentials):
    """The name axes counts a login under: the account's email, in lowercase, whether
    the login came by email (allauth's pages), by username (the admin's own login page),
    or as axes' own reset after a successful login (also by username). So
    "Ada@Example.com", "ada@example.com" and ada's username all count together."""
    credentials = credentials or {}
    name = credentials.get("email")
    if name is None and credentials.get("username"):
        name = email_of(credentials["username"]) or credentials["username"]
    if name is None and request is not None:
        data = getattr(request, "POST", {})
        name = data.get("login") or data.get("email") or data.get("username")
    return name.strip().lower() if isinstance(name, str) else name


def email_of(username):
    """The email of the account with this username, if there is one."""
    users = get_user_model()
    try:
        user = users._default_manager.get_by_natural_key(username)
    except users.DoesNotExist:
        return None
    return getattr(user, users.get_email_field_name(), "") or None
