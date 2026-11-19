"""Signal receivers for accounts, connected in apps.py (connect_receivers)."""

from allauth.account.signals import password_reset
from allauth.core import context
from django.contrib.auth import get_user_model
from django.db import transaction
from django.db.models.signals import post_save

from .services import confirm_address_by_reset, send_account_created_email


def email_accounts_created_in_the_admin(sender, instance, created, **kwargs):
    """Staff added this account in the Django admin: once it's saved, email the person a
    link to choose their password. Accounts made any other way (signup, the shell,
    createsuperuser) aren't emailed."""
    request = context.request
    match = getattr(request, "resolver_match", None)
    if created and match is not None and "admin" in match.app_names:
        transaction.on_commit(lambda: send_with_request(instance, request))


def send_with_request(user, request):
    with context.request_context(request):
        send_account_created_email(user)


def confirm_address_after_reset(sender, user, **kwargs):
    confirm_address_by_reset(user)


def connect_receivers():
    post_save.connect(
        email_accounts_created_in_the_admin,
        sender=get_user_model(),
        dispatch_uid="capy_auth_account_created_in_admin",
    )
    password_reset.connect(confirm_address_after_reset, dispatch_uid="capy_auth_reset_confirms")
