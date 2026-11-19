"""Changes to people's email addresses outside allauth's own pages: confirming one by
hand, the "choose your password" email for accounts staff create, and confirming an
address by a completed password reset."""

from allauth.account import app_settings
from allauth.account.adapter import get_adapter
from allauth.account.models import EmailAddress
from allauth.account.utils import user_email, user_pk_to_url_str
from allauth.core import context
from allauth.utils import build_absolute_uri
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.urls import reverse
from django.utils.translation import ngettext

from capy_auth.bans.selectors import is_banned_email

ACCOUNT_CREATED_EMAIL = "capy_auth/email/account_created"


class AddressNotConfirmed(Exception):
    """mark_email_verified couldn't confirm the address; the message says why."""


def normalized_address(email):
    """How allauth stores an address: no spaces around it, lowercase."""
    return (email or "").strip().lower()


def mark_email_verified(email):
    """Confirms the address on the account using it (its own email, or an address in
    allauth's list), adding it to the account's addresses if needed. It becomes the
    main address when the account has no confirmed one (allauth then keeps the
    account's email in step). Returns the account and whether it's the main address."""
    email = normalized_address(email)
    if not email:
        raise AddressNotConfirmed("Give the email address to confirm.")
    if is_banned_email(email):
        raise AddressNotConfirmed(f"{email} is on the ban list, so it can't be confirmed.")
    users = list(accounts_with_address(email)[:2])
    if not users:
        raise AddressNotConfirmed(f"No account uses {email}.")
    if len(users) > 1:
        raise AddressNotConfirmed(
            f"More than one account uses {email}: confirm it on the right account in the "
            "admin's email address list instead."
        )
    try:
        with transaction.atomic():
            address = confirm_on_account(users[0], email)
    except IntegrityError as error:
        raise AddressNotConfirmed(
            f"{email} couldn't be confirmed: another account has it confirmed, or the "
            "account's addresses changed at the same moment. Check them in the admin."
        ) from error
    return users[0], address.primary


def accounts_with_address(email):
    addresses = EmailAddress.objects.filter(email=email).values("user_id")
    matches = Q(pk__in=addresses)
    if field := app_settings.USER_MODEL_EMAIL_FIELD:
        matches |= Q(**{f"{field}__iexact": email})
    return get_user_model().objects.filter(matches)


def confirm_on_account(user, email):
    address, _ = EmailAddress.objects.get_or_create(user=user, email=email)
    address.verified = True
    address.save()
    main = EmailAddress.objects.get_primary(user)
    if main is None or (not main.verified and main.pk != address.pk):
        address.set_as_primary()
    return address


def send_account_created_email(user):
    """Gives an account staff created in the admin its address (unconfirmed; the main
    one if it has none) and emails it a one-time link to choose a password. Sends
    nothing, and returns False, when another account has the address confirmed: the
    link would hand that person a second account."""
    email = normalized_address(user_email(user))
    if not email:
        return False
    if EmailAddress.objects.filter(email=email, verified=True).exclude(user=user).exists():
        return False
    has_main = EmailAddress.objects.filter(user=user, primary=True).exists()
    EmailAddress.objects.get_or_create(
        user=user, email=email, defaults={"primary": not has_main, "verified": False}
    )
    adapter = get_adapter()
    token = app_settings.PASSWORD_RESET_TOKEN_GENERATOR().make_token(user)
    # The key in the format allauth's own reset email uses ("<uid>-<token>", in
    # allauth/account/internal/flows/password_reset.py); a test follows the link.
    url = adapter.get_reset_password_from_key_url(f"{user_pk_to_url_str(user)}-{token}")
    adapter.send_mail(
        ACCOUNT_CREATED_EMAIL,
        email,
        {
            "user": user,
            "password_reset_url": url,
            "link_lifetime": link_lifetime(),
            "login_url": build_absolute_uri(context.request, reverse("account_login")),
        },
    )
    return True


def link_lifetime():
    """How long a password link works (PASSWORD_RESET_TIMEOUT), in words."""
    minutes = settings.PASSWORD_RESET_TIMEOUT // 60
    if minutes % 60:
        return ngettext("%(count)d minute", "%(count)d minutes", minutes) % {"count": minutes}
    hours = minutes // 60
    return ngettext("%(count)d hour", "%(count)d hours", hours) % {"count": hours}


def confirm_address_by_reset(user):
    """A completed password reset confirms the account's address when it's the
    account's only one and its own email: the link went there, so the person can read
    it (allauth's reset by code confirms it the same way). This relies on two allauth
    defaults, checked again on each allauth upgrade: resets go only by email, and the
    reset link stops working when the account's addresses change (allauth's
    email-aware token generator; a project mustn't replace it)."""
    addresses = list(user.emailaddress_set.all())
    email = normalized_address(user_email(user))
    if len(addresses) == 1 and not addresses[0].verified and addresses[0].email == email:
        addresses[0].set_verified()
