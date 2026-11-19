"""Changes made by the ban list: suspending and reactivating accounts, and recording
attempts to use a banned address."""

import logging

from allauth.account.adapter import get_adapter
from allauth.account.utils import user_email
from django.contrib.auth import get_user_model
from django.db import transaction

from .models import AttemptKind, BannedEmail, BannedEmailAttempt
from .selectors import accounts_held_by_bans, accounts_using, normalized

logger = logging.getLogger("capy_auth")

BANNED_ADDRESS_NOTICE = "capy_auth/email/banned_address"
SUSPENDED_NOTICE = "capy_auth/email/account_suspended"
NOTICES = (BANNED_ADDRESS_NOTICE, SUSPENDED_NOTICE)


def suspend_accounts(ban):
    """Deactivates (never deletes) the accounts using the banned address, remembers
    them on the ban and emails each one. Their sessions end on their next page load:
    Django doesn't keep inactive accounts logged in. An account another ban already
    suspended is remembered too, so lifting either ban alone doesn't reactivate it; one
    staff deactivated by hand is left alone. Returns how many were suspended."""
    matches = accounts_using(ban.email)
    accounts = list(matches.filter(is_active=True))
    with transaction.atomic():
        for account in accounts:
            account.is_active = False
            account.save(update_fields=["is_active"])
        ban.suspended_accounts.add(*accounts, *accounts_held_by_bans(matches))
    for account in accounts:
        get_adapter().send_mail(SUSPENDED_NOTICE, user_email(account) or ban.email, {})
    return len(accounts)


def lift_bans(bans):
    """Deletes the bans and reactivates the accounts they suspended, except any still
    suspended by another ban. Returns how many accounts were reactivated."""
    bans = list(bans)
    suspended = {account.pk for ban in bans for account in ban.suspended_accounts.all()}
    with transaction.atomic():
        BannedEmail.objects.filter(pk__in=[ban.pk for ban in bans]).delete()
        accounts = get_user_model().objects.filter(pk__in=suspended, is_active=False)
        return accounts.exclude(pk__in=accounts_held_by_bans(accounts)).update(is_active=True)


def record_attempt(email, request):
    """Someone tried to sign up with, or add, a banned address. Kept for staff and
    logged as a warning (without the address)."""
    signed_in = request is not None and request.user.is_authenticated
    attempt = BannedEmailAttempt.objects.create(
        email=normalized(email),
        kind=AttemptKind.ADD_EMAIL if signed_in else AttemptKind.SIGNUP,
        account=request.user if signed_in else None,
        ip_address=get_adapter().get_client_ip(request) if request is not None else None,
    )
    logger.warning(
        "A banned email address was tried (%s); see attempt %s in the admin.",
        attempt.kind,
        attempt.pk,
    )
