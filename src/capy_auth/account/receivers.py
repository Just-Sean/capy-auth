"""Signal receivers for accounts, connected in apps.py (connect_receivers)."""

from allauth.account.signals import password_reset
from allauth.account.utils import user_email
from allauth.core import context
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.db import transaction
from django.db.models.signals import post_save
from django.utils.translation import gettext as _

from .services import confirm_address_by_reset, send_account_created_email


def email_accounts_created_in_the_admin(sender, instance, created, **kwargs):
    """Staff added this account on the admin's "add user" page: once it's saved, email
    the person a link to choose their password. Accounts made any other way (signup,
    other admin pages, the shell, createsuperuser, a login system that creates users)
    aren't emailed. capy-auth never changes the project's user admin, so it notices
    the save during that page's request instead."""
    request = context.request
    if created and is_the_user_admins_add_page(request):
        transaction.on_commit(lambda: send_and_tell_staff(instance, request))


def is_the_user_admins_add_page(request):
    match = getattr(request, "resolver_match", None)
    staff = getattr(request, "user", None)
    options = get_user_model()._meta
    return (
        match is not None
        and "admin" in match.app_names
        and match.url_name == f"{options.app_label}_{options.model_name}_add"
        and staff is not None
        and staff.is_authenticated
        and staff.is_staff
    )


def send_and_tell_staff(user, request):
    with context.request_context(request):
        sent = send_account_created_email(user)
    email = user_email(user)
    if sent:
        messages.info(request, _("A link to choose a password was emailed to %s.") % email)
    elif email:
        messages.warning(
            request,
            _("No email was sent: another account has %s confirmed.") % email,
        )


def confirm_address_after_reset(sender, user, **kwargs):
    confirm_address_by_reset(user)


def connect_receivers():
    post_save.connect(
        email_accounts_created_in_the_admin,
        sender=get_user_model(),
        dispatch_uid="capy_auth_account_created_in_admin",
    )
    password_reset.connect(confirm_address_after_reset, dispatch_uid="capy_auth_reset_confirms")
