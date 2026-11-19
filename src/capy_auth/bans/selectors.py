"""Reading the ban list."""

from allauth.account import app_settings
from allauth.account.models import EmailAddress
from django.contrib.auth import get_user_model
from django.db.models import Q

from .models import BannedEmail


def normalized(email):
    return (email or "").strip().lower()


def is_banned_email(email):
    """Whether the address is on the ban list, however it's typed."""
    email = normalized(email)
    return bool(email) and BannedEmail.objects.filter(email=email).exists()


def accounts_using(email):
    """Accounts whose own email, or one of whose confirmed addresses, is this one."""
    email = normalized(email)
    confirmed = EmailAddress.objects.filter(email__iexact=email, verified=True)
    matches = Q(pk__in=confirmed.values("user_id"))
    if email_field := app_settings.USER_MODEL_EMAIL_FIELD:
        matches |= Q(**{f"{email_field}__iexact": email})
    return get_user_model().objects.filter(matches)


def accounts_held_by_bans(accounts):
    """Those of the accounts that a ban has suspended."""
    return accounts.filter(pk__in=BannedEmail.objects.values("suspended_accounts"))
