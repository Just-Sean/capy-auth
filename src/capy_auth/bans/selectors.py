"""Reading the ban list."""

from allauth.account import app_settings
from allauth.account.models import EmailAddress
from django.contrib.auth import get_user_model
from django.db.models import Q

from .models import BannedEmail, normalize_email


def is_banned_email(email):
    """Whether the address is on the ban list, however it's typed."""
    email = normalize_email(email)
    return bool(email) and BannedEmail.objects.filter(email=email).exists()


def accounts_using(email):
    """Accounts whose own email, or one of whose confirmed addresses, is this one."""
    email = normalize_email(email)
    confirmed = EmailAddress.objects.filter(email__iexact=email, verified=True)
    matches = Q(pk__in=confirmed.values("user_id"))
    if email_field := app_settings.USER_MODEL_EMAIL_FIELD:
        matches |= Q(**{f"{email_field}__iexact": email})
    return get_user_model().objects.filter(matches)


def suspended_by_bans():
    """The IDs of every account a ban has suspended. Read from the table linking bans to
    accounts, which never holds an empty ID: a NULL in a "not in" list would match
    nothing, and lifting a ban would then reactivate nobody."""
    links = BannedEmail.suspended_accounts.through.objects
    return links.values(BannedEmail.suspended_accounts.field.m2m_reverse_field_name())
