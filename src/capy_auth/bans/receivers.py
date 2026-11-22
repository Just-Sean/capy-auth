"""Signal receivers for the ban list, connected in apps.py (connect_receivers)."""

from allauth.account.models import EmailAddress
from allauth.account.signals import _add_email
from allauth.core import context
from django.db.models.signals import pre_save

from .models import AttemptKind
from .selectors import is_banned_email
from .services import record_attempt


def record_banned_address_added(sender, email, user, **kwargs):
    """allauth sends this when someone adds an address to their account and it passed
    the form's checks (from its add-email form, the website's and the API's; nowhere
    else). The page goes on as normal; the attempt is recorded for staff. allauth marks
    the signal internal, so tests check it still fires after each allauth upgrade."""
    if is_banned_email(email):
        record_attempt(email, AttemptKind.ADD_EMAIL, context.request, account=user)


def never_store_a_banned_address_as_confirmed(sender, instance, **kwargs):
    """The last line of defense: whichever way an address gets confirmed (a code, a
    link, a login or reset code sent before the ban, staff ticking "verified" in the
    admin), a banned one is saved unconfirmed."""
    if instance.verified and is_banned_email(instance.email):
        instance.verified = False


def connect_receivers():
    _add_email.connect(record_banned_address_added, dispatch_uid="capy_auth_banned_add")
    pre_save.connect(
        never_store_a_banned_address_as_confirmed,
        sender=EmailAddress,
        dispatch_uid="capy_auth_banned_unconfirmed",
    )
