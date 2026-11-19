"""Changes to people's email addresses outside allauth's own pages: confirming one by
hand, the "choose your password" email for accounts staff create, and confirming an
address by a completed password reset."""

from allauth.account import app_settings
from allauth.account.adapter import get_adapter
from allauth.account.models import EmailAddress
from allauth.account.utils import user_email, user_pk_to_url_str
from django.contrib.auth import get_user_model
from django.db.models import Q

from capy_auth.bans.selectors import is_banned_email

ACCOUNT_CREATED_EMAIL = "capy_auth/email/account_created"


class AddressNotConfirmed(Exception):
    """mark_email_verified couldn't confirm the address; the message says why."""


def mark_email_verified(email):
    """Confirms the address on the account using it (its own email, or an address in
    allauth's list) and makes it primary if the account has none. Returns the account."""
    email = email.strip().lower()
    if is_banned_email(email):
        raise AddressNotConfirmed(f"{email} is on the ban list, so it can't be confirmed.")
    matches = Q(emailaddress__email__iexact=email)
    if field := app_settings.USER_MODEL_EMAIL_FIELD:
        matches |= Q(**{f"{field}__iexact": email})
    users = get_user_model().objects.filter(matches).distinct()
    if len(users) != 1:
        raise AddressNotConfirmed(
            f"No account uses {email}." if not users else f"{len(users)} accounts use {email}."
        )
    user = users[0]
    address = EmailAddress.objects.filter(user=user, email__iexact=email).first()
    if address is None:
        address = EmailAddress(user=user, email=email)
    address.primary = address.primary or not user.emailaddress_set.filter(primary=True).exists()
    address.verified = True
    address.save()
    return user


def send_account_created_email(user):
    """Gives an account staff created in the admin its address as an unconfirmed primary
    address, and emails it a one-time link to choose a password (allauth's password
    reset link, valid for PASSWORD_RESET_TIMEOUT)."""
    email = user_email(user)
    if not email:
        return
    EmailAddress.objects.get_or_create(
        user=user, email=email.lower(), defaults={"primary": True, "verified": False}
    )
    adapter = get_adapter()
    token = app_settings.PASSWORD_RESET_TOKEN_GENERATOR().make_token(user)
    url = adapter.get_reset_password_from_key_url(f"{user_pk_to_url_str(user)}-{token}")
    adapter.send_mail(ACCOUNT_CREATED_EMAIL, email, {"user": user, "password_reset_url": url})


def confirm_address_by_reset(user):
    """A password reset link goes only to an address on the account. When the account
    has just one address and it's the account's own email, the link went there, so
    completing the reset proves the person can read it: confirm it."""
    addresses = list(user.emailaddress_set.all())
    email = (user_email(user) or "").lower()
    if len(addresses) == 1 and not addresses[0].verified and addresses[0].email.lower() == email:
        addresses[0].set_verified()
