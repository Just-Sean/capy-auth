"""Changes made by the ban list: suspending and reactivating accounts, and recording
attempts to use a banned address."""

import logging

from allauth.account.adapter import get_adapter
from allauth.account.utils import user_email
from allauth.core import context
from django.apps import apps
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured, PermissionDenied
from django.db import transaction

from .models import BannedEmailAttempt, normalize_email
from .selectors import accounts_using, suspended_by_bans

logger = logging.getLogger("capy_auth")

BANNED_ADDRESS_NOTICE = "capy_auth/email/banned_address"
SUSPENDED_NOTICE = "capy_auth/email/account_suspended"
NOTICES = (BANNED_ADDRESS_NOTICE, SUSPENDED_NOTICE)


def suspend_accounts(ban):
    """Deactivates (never deletes) the accounts using the newly banned address,
    remembers them on the ban and emails each one once the change is saved. Their
    sessions are ended (and Django refuses inactive accounts anyway), so lifting the
    ban signs nobody back in. An account another ban already suspended is remembered
    too, so lifting either ban alone doesn't reactivate it; one staff deactivated by
    hand is left alone. Returns how many were suspended."""
    matches = accounts_using(ban.email)
    accounts = list(matches.filter(is_active=True))
    with transaction.atomic():
        for account in accounts:
            account.is_active = False
            account.save(update_fields=["is_active"])
        ban.suspended_accounts.add(*accounts, *matches.filter(pk__in=suspended_by_bans()))
        end_sessions(accounts)
    addresses = [user_email(account) or ban.email for account in accounts]
    request = context.request
    transaction.on_commit(lambda: send_suspension_notices(addresses, request))
    return len(accounts)


def end_sessions(accounts):
    """Ends every recorded session of these accounts (allauth's user sessions, which
    capy-auth records for every sign-in). E006 makes sure the app is installed; this
    only skips the step if it isn't, rather than failing a ban."""
    if not apps.is_installed("allauth.usersessions"):
        return
    from allauth.usersessions.models import UserSession

    for session in UserSession.objects.filter(user__in=accounts):
        session.end()


def send_suspension_notices(addresses, request):
    """Runs once the suspension is saved, so nobody is told about one that didn't
    happen. The request is kept for the emails' site name and links."""
    with context.request_context(request):
        for address in addresses:
            get_adapter().send_mail(SUSPENDED_NOTICE, address, {})


def lift_bans(bans):
    """Deletes the bans (a queryset) and reactivates the accounts they suspended, except
    any still suspended by another ban. Returns the reactivated accounts."""
    with transaction.atomic():
        suspended = list(bans.values_list("suspended_accounts", flat=True))
        bans.delete()
        accounts = list(
            get_user_model()
            .objects.filter(pk__in=suspended, is_active=False)
            .exclude(pk__in=suspended_by_bans())
        )
        for account in accounts:
            account.is_active = True
            account.save(update_fields=["is_active"])
    return accounts


def record_attempt(email, kind, request, account=None):
    """Someone tried to sign up with, or add, a banned address. Kept for staff and
    logged as a warning (without the address)."""
    attempt = BannedEmailAttempt.objects.create(
        email=normalize_email(email), kind=kind, account=account, ip_address=client_ip(request)
    )
    logger.warning(
        "A banned email address was tried (%s); see attempt %s in the admin.",
        attempt.kind,
        attempt.pk,
    )


def client_ip(request):
    """The visitor's address as allauth reads it, or None when it can't be read (no
    request, or a proxy setup that doesn't match ALLAUTH_TRUSTED_PROXY_COUNT). Never an
    error: that would happen only for banned addresses and give the ban away."""
    if request is None:
        return None
    try:
        return get_adapter().get_client_ip(request)
    except PermissionDenied, ImproperlyConfigured:
        return None
