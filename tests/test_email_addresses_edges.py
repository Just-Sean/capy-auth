"""Edge cases for email addresses and existing users: blank and shared addresses,
the migration on real migration history, the email page's limits, accounts created
on the real admin "add user" page, and when a reset does and doesn't confirm."""

import importlib
import time
from io import StringIO
from types import SimpleNamespace

import pytest
from allauth.account.models import EmailAddress
from django import forms
from django.apps import apps
from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import AdminUserCreationForm
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core import mail
from django.core.management import CommandError, call_command
from django.db import connection
from django.test import Client
from django.urls import reverse

from capy_auth.account.services import confirm_address_by_reset
from capy_auth.bans.models import BannedEmail
from tests.accounts import (
    ACCOUNT_PAGE,
    NEW_PASSWORD,
    PASSWORD,
    RESET,
    code_from,
    log_in,
    reset_link,
)
from tests.staff import two_step_client

EMAIL_PAGE = reverse("account_email")
existing_users = importlib.import_module("capy_auth.migrations.0004_existing_users_email_addresses")


def is_djangos_user_model():
    return get_user_model()._meta.label == "auth.User"


def plain_user(email, username=None, **extra):
    return get_user_model().objects.create_user(
        username=username or (email.split("@")[0].strip() or "nobody"),
        email=email,
        password=PASSWORD,
        **extra,
    )


def run_the_migration():
    existing_users.add_missing_addresses(apps, SimpleNamespace(connection=connection))


def logged_in_and_confirmed(email="ada@example.com"):
    client = Client()
    log_in(client, email=email)
    client.post(reverse("account_reauthenticate"), {"password": PASSWORD})
    return client


# --- mark_email_verified -------------------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize("typed", ["", "   "])
def test_the_command_refuses_a_blank_address(typed, ada):
    """A blank argument must never 'confirm' an empty address on whichever account
    happens to have a blank email field."""
    if not is_djangos_user_model():
        pytest.skip("capy-project's user model needs an email")
    plain_user("", username="noemail")
    with pytest.raises(CommandError):
        call_command("mark_email_verified", typed, stdout=StringIO())
    assert not EmailAddress.objects.filter(email="").exists()


@pytest.mark.django_db
def test_the_command_refuses_a_blank_address_with_no_blank_users(ada):
    with pytest.raises(CommandError):
        call_command("mark_email_verified", "", stdout=StringIO())


@pytest.mark.django_db
def test_the_command_on_an_address_confirmed_elsewhere_refuses(ada):
    """Bob's own email field is ada@example.com (auth.User allows duplicates): two
    accounts, refused, Bob gets nothing."""
    if not is_djangos_user_model():
        pytest.skip("emails are unique")
    bob = plain_user("ada@example.com", username="bob")
    with pytest.raises(CommandError, match="More than one account"):
        call_command("mark_email_verified", "ada@example.com")
    assert not bob.emailaddress_set.exists()


@pytest.mark.django_db
def test_the_command_confirms_an_existing_unconfirmed_primary_in_place():
    root = plain_user("root@example.com")
    run_the_migration()
    call_command("mark_email_verified", "ROOT@example.com", stdout=StringIO())
    address = root.emailaddress_set.get()
    assert (address.email, address.primary, address.verified) == ("root@example.com", True, True)


@pytest.mark.django_db
def test_the_command_on_a_banned_unicode_domain_refuses():
    plain_user("x@bücher.example", username="x")
    BannedEmail.objects.create(email="x@xn--bcher-kva.example")
    with pytest.raises(CommandError, match="ban list"):
        call_command("mark_email_verified", "x@bücher.example")
    assert not EmailAddress.objects.filter(verified=True).exists()


# --- The migration -------------------------------------------------------------------------


@pytest.mark.django_db
def test_the_migration_skips_a_whitespace_only_email():
    if not is_djangos_user_model():
        pytest.skip("capy-project's user model strips and needs an email")
    plain_user("   ", username="spaces")
    run_the_migration()
    assert not EmailAddress.objects.filter(email="").exists()


@pytest.mark.django_db
def test_the_migration_leaves_users_who_already_have_some_address(ada):
    other = plain_user("other@example.com")
    EmailAddress.objects.create(user=other, email="different@example.com", verified=False)
    run_the_migration()
    assert list(other.emailaddress_set.values_list("email", flat=True)) == ["different@example.com"]


@pytest.mark.django_db
def test_the_migration_gives_users_sharing_an_email_each_an_unconfirmed_address():
    if not is_djangos_user_model():
        pytest.skip("emails are unique")
    one = plain_user("Twin@Example.com", username="one")
    two = plain_user("twin@example.com ", username="two")
    run_the_migration()
    for user in (one, two):
        address = user.emailaddress_set.get()
        assert (address.email, address.primary, address.verified) == (
            "twin@example.com",
            True,
            False,
        )


@pytest.mark.django_db
def test_a_migrated_user_with_a_mixed_case_email_logs_in_with_a_code_then_freely():
    root = plain_user("Root@Example.COM")
    run_the_migration()
    client = Client()
    response = log_in(client, email="root@example.com")
    assert response.url != ACCOUNT_PAGE
    client.post(response.url, {"code": code_from(mail.outbox[-1])})
    assert root.emailaddress_set.get().verified
    assert log_in(Client(), email="root@example.com").url == ACCOUNT_PAGE


@pytest.mark.django_db
def test_a_migrated_user_with_spaces_round_their_email_is_confirmed_by_a_reset():
    """auth.User keeps the spaces in the email field; the migration strips them. A
    completed reset should still confirm the (only) address."""
    if not is_djangos_user_model():
        pytest.skip("capy-project's user model strips the email")
    root = plain_user(" root@example.com ")
    run_the_migration()
    confirm_address_by_reset(root)
    assert root.emailaddress_set.get().verified


# --- The email page ------------------------------------------------------------------------


@pytest.mark.django_db
def test_adding_an_address_another_account_has_confirmed_never_adds_it(ada):
    bob = plain_user("bob@example.com", username="bob")
    EmailAddress.objects.create(user=bob, email="bob@example.com", primary=True, verified=True)
    client = logged_in_and_confirmed()
    response = client.post(EMAIL_PAGE, {"email": "bob@example.com", "action_add": ""})
    if mail.outbox and response.status_code == 302:
        try:
            client.post(response.url, {"code": code_from(mail.outbox[-1])})
        except AttributeError:
            pass  # not a code email (e.g. "someone tried to add your address")
    assert not ada.emailaddress_set.filter(email="bob@example.com").exists()
    assert bob.emailaddress_set.get().verified


@pytest.mark.django_db
def test_an_unconfirmed_address_cant_be_made_primary(ada):
    EmailAddress.objects.create(user=ada, email="ada.work@example.com", verified=False)
    client = logged_in_and_confirmed()
    client.post(EMAIL_PAGE, {"email": "ada.work@example.com", "action_primary": ""})
    ada.refresh_from_db()
    assert ada.email == "ada@example.com"
    assert EmailAddress.objects.get(email="ada@example.com").primary


@pytest.mark.django_db
def test_a_new_code_can_be_sent_for_an_unconfirmed_address(ada):
    EmailAddress.objects.create(user=ada, email="ada.work@example.com", verified=False)
    client = logged_in_and_confirmed()
    response = client.post(EMAIL_PAGE, {"email": "ada.work@example.com", "action_send": ""})
    assert response.status_code == 302
    assert mail.outbox[-1].to == ["ada.work@example.com"]
    client.post(response.url, {"code": code_from(mail.outbox[-1])})
    assert EmailAddress.objects.get(email="ada.work@example.com").verified


@pytest.mark.django_db
def test_a_secondary_address_can_be_removed_but_not_without_the_password(ada):
    EmailAddress.objects.create(user=ada, email="ada.work@example.com", verified=True)
    client = Client()
    log_in(client)
    response = client.post(EMAIL_PAGE, {"email": "ada.work@example.com", "action_remove": ""})
    assert response.url.startswith(reverse("account_reauthenticate"))
    assert ada.emailaddress_set.count() == 2
    client.post(reverse("account_reauthenticate"), {"password": PASSWORD})
    client.post(EMAIL_PAGE, {"email": "ada.work@example.com", "action_remove": ""})
    assert list(ada.emailaddress_set.values_list("email", flat=True)) == ["ada@example.com"]


@pytest.mark.django_db
def test_someone_elses_address_cant_be_removed_from_my_page(ada):
    bob = plain_user("bob@example.com", username="bob")
    EmailAddress.objects.create(user=bob, email="bob@example.com", primary=True, verified=True)
    EmailAddress.objects.create(user=bob, email="bob2@example.com", verified=True)
    client = logged_in_and_confirmed()
    client.post(EMAIL_PAGE, {"email": "bob2@example.com", "action_remove": ""})
    client.post(EMAIL_PAGE, {"email": "bob2@example.com", "action_primary": ""})
    assert bob.emailaddress_set.count() == 2
    bob.refresh_from_db()
    assert bob.email == "bob@example.com"


@pytest.mark.django_db
def test_the_email_page_needs_a_login():
    response = Client().get(EMAIL_PAGE)
    assert response.status_code == 302
    assert reverse("account_login") in response.url


# --- Accounts created by staff, through the real admin add page -------------------------------


class WithEmail(AdminUserCreationForm):
    """capy-project's admin asks for the email on the add page."""

    email = forms.EmailField()

    class Meta(AdminUserCreationForm.Meta):
        fields = ("username", "email")


@pytest.fixture
def admin_with_email_on_add(monkeypatch, db):
    if not is_djangos_user_model():
        pytest.skip("the stand-in project has no admin for capy-project's user model")
    user_admin = admin.site._registry[get_user_model()]
    monkeypatch.setattr(user_admin, "add_form", WithEmail)
    monkeypatch.setattr(
        user_admin,
        "add_fieldsets",
        ((None, {"fields": ("username", "email", "usable_password", "password1", "password2")}),),
    )
    superuser = get_user_model().objects.create_superuser(
        username="admin", email="admin@example.com", password=PASSWORD
    )
    return two_step_client(superuser)


def add_in_admin(client, email, username="carol", usable=True):
    data = {"username": username, "email": email}
    if usable:
        data |= {"usable_password": "true", "password1": PASSWORD, "password2": PASSWORD}
    else:
        data |= {"usable_password": "false"}
    return client.post(reverse("admin:auth_user_add"), data)


def link_path(message):
    return message.body.split("http://testserver", 1)[1].split()[0]


def choose_password(client, path):
    page = client.get(path, follow=True)
    form_url = page.redirect_chain[-1][0] if page.redirect_chain else path
    return client.post(form_url, {"password1": NEW_PASSWORD, "password2": NEW_PASSWORD})


@pytest.mark.django_db(transaction=True)
def test_the_real_admin_add_page_sends_the_link_and_it_confirms_the_address(
    admin_with_email_on_add,
):
    response = add_in_admin(admin_with_email_on_add, "Carol@Example.com")
    assert response.status_code == 302, response.content
    created = [m for m in mail.outbox if "created for you" in m.subject]
    assert len(created) == 1 and [a.lower() for a in created[0].to] == ["carol@example.com"]
    choose_password(Client(), link_path(created[0]))
    carol = get_user_model().objects.get(username="carol")
    assert carol.emailaddress_set.get().verified
    assert log_in(Client(), email="carol@example.com", password=NEW_PASSWORD).url == ACCOUNT_PAGE


@pytest.mark.django_db(transaction=True)
def test_the_admin_link_works_for_an_account_without_a_usable_password(
    admin_with_email_on_add,
):
    add_in_admin(admin_with_email_on_add, "carol@example.com", usable=False)
    created = [m for m in mail.outbox if "created for you" in m.subject]
    assert len(created) == 1
    assert choose_password(Client(), link_path(created[0])).status_code == 302
    assert log_in(Client(), email="carol@example.com", password=NEW_PASSWORD).url == ACCOUNT_PAGE


@pytest.mark.django_db(transaction=True)
def test_the_admin_link_works_only_once(admin_with_email_on_add):
    add_in_admin(admin_with_email_on_add, "carol@example.com")
    path = link_path([m for m in mail.outbox if "created for you" in m.subject][0])
    choose_password(Client(), path)
    carol = get_user_model().objects.get(username="carol")
    second = Client().get(path, follow=True)
    assert b'name="password1"' not in second.content
    carol.refresh_from_db()
    assert carol.check_password(NEW_PASSWORD)


@pytest.mark.django_db(transaction=True)
def test_the_admin_link_expires(admin_with_email_on_add, settings, monkeypatch):
    add_in_admin(admin_with_email_on_add, "carol@example.com")
    path = link_path([m for m in mail.outbox if "created for you" in m.subject][0])
    later = time.time() + settings.PASSWORD_RESET_TIMEOUT + 60
    from datetime import datetime

    monkeypatch.setattr(
        PasswordResetTokenGenerator, "_now", lambda self: datetime.fromtimestamp(later)
    )
    page = Client().get(path, follow=True)
    assert b'name="password1"' not in page.content


@pytest.mark.django_db(transaction=True)
def test_a_banned_address_added_in_the_admin_gets_only_the_ban_notice(admin_with_email_on_add):
    BannedEmail.objects.create(email="carol@example.com")
    mail.outbox.clear()
    add_in_admin(admin_with_email_on_add, "carol@example.com")
    assert all("created for you" not in m.subject for m in mail.outbox)
    assert all("/password/reset/key/" not in m.body for m in mail.outbox)


@pytest.mark.django_db(transaction=True)
def test_an_admin_add_that_fails_validation_sends_nothing(admin_with_email_on_add):
    response = admin_with_email_on_add.post(
        reverse("admin:auth_user_add"),
        {
            "username": "carol",
            "email": "carol@example.com",
            "usable_password": "true",
            "password1": PASSWORD,
            "password2": "different",
        },
    )
    assert response.status_code == 200
    assert mail.outbox == []


@pytest.mark.django_db(transaction=True)
def test_editing_a_user_in_the_admin_sends_nothing(admin_with_email_on_add, ada):
    mail.outbox.clear()
    admin_with_email_on_add.post(
        reverse("admin:auth_user_change", args=[ada.pk]),
        {
            "username": "ada",
            "email": "ada@example.com",
            "is_active": "on",
            "date_joined_0": "2026-01-01",
            "date_joined_1": "00:00:00",
        },
    )
    assert all("created for you" not in m.subject for m in mail.outbox)


# --- The reset confirms the address only in the right cases ---------------------------------


@pytest.mark.django_db
def test_a_reset_on_an_account_with_two_addresses_confirms_neither_unconfirmed_one(ada):
    """Ada (confirmed primary) also has an unconfirmed address; the reset goes to the
    unconfirmed one, and completing it doesn't confirm it (the safe choice)."""
    EmailAddress.objects.create(user=ada, email="ada.work@example.com", verified=False)
    client = Client()
    client.post(RESET, {"email": "ada.work@example.com"})
    message = mail.outbox[-1]
    assert message.to == ["ada.work@example.com"]
    path = reset_link(message)
    page = client.get(path, follow=True)
    client.post(page.redirect_chain[-1][0], {"password1": NEW_PASSWORD, "password2": NEW_PASSWORD})
    ada.refresh_from_db()
    assert ada.check_password(NEW_PASSWORD)
    assert not EmailAddress.objects.get(email="ada.work@example.com").verified


@pytest.mark.django_db
def test_a_reset_doesnt_confirm_an_only_address_that_isnt_the_accounts_email():
    if not is_djangos_user_model():
        pytest.skip("the email field and the address can't differ in a way login uses")
    bob = plain_user("bob@example.com", username="bob")
    EmailAddress.objects.create(user=bob, email="other@example.com", primary=True, verified=False)
    confirm_address_by_reset(bob)
    assert not bob.emailaddress_set.get().verified


@pytest.mark.django_db
def test_a_reset_doesnt_confirm_a_banned_address():
    bob = plain_user("bob@example.com", username="bob")
    EmailAddress.objects.create(user=bob, email="bob@example.com", primary=True, verified=False)
    BannedEmail.objects.create(email="bob@example.com")
    confirm_address_by_reset(bob)
    assert not bob.emailaddress_set.get().verified


@pytest.mark.django_db
def test_a_reset_doesnt_confirm_an_address_another_account_has_confirmed():
    if not is_djangos_user_model():
        pytest.skip("emails are unique")
    ada = plain_user("ada@example.com", username="ada")
    EmailAddress.objects.create(user=ada, email="ada@example.com", primary=True, verified=True)
    copy = plain_user("ada@example.com", username="copy")
    EmailAddress.objects.create(user=copy, email="ada@example.com", primary=True, verified=False)
    confirm_address_by_reset(copy)
    assert not copy.emailaddress_set.get().verified


@pytest.mark.django_db(transaction=True)
def test_the_real_migration_runs_backwards_and_forwards_with_existing_users():
    """Through the migration executor (historical models), not the function directly."""
    from django.db.migrations.executor import MigrationExecutor

    executor = MigrationExecutor(connection)
    executor.migrate([("capy_auth", "0003_ban_list")])
    executor.loader.build_graph()
    old_apps = executor.loader.project_state([("capy_auth", "0003_ban_list")]).apps
    user_model = old_apps.get_model(*get_user_model()._meta.label.split("."))
    fields = {"username": "old", "email": "Old@Example.com", "password": "x"}
    pk = user_model.objects.create(**fields).pk
    executor = MigrationExecutor(connection)
    executor.migrate([("capy_auth", "0004_existing_users_email_addresses")])
    address = EmailAddress.objects.get(user_id=pk)
    assert (address.email, address.primary, address.verified) == ("old@example.com", True, False)
    executor = MigrationExecutor(connection)  # back to the newest, for the tests after it
    executor.migrate(executor.loader.graph.leaf_nodes("capy_auth"))


# --- More flows ------------------------------------------------------------------------------


@pytest.mark.django_db
def test_a_superuser_made_after_the_migration_is_asked_for_a_code_and_the_command_lets_them_in():
    """The README's new-server case: migrate first, then createsuperuser."""
    run_the_migration()
    root = get_user_model().objects.create_superuser(
        username="root", email="root@example.com", password=PASSWORD
    )
    response = log_in(Client(), email="root@example.com")
    assert response.url != ACCOUNT_PAGE
    call_command("mark_email_verified", "root@example.com", stdout=StringIO())
    address = root.emailaddress_set.get()
    assert (address.verified, address.primary) == (True, True)
    assert log_in(Client(), email="root@example.com").url == ACCOUNT_PAGE


@pytest.mark.django_db
def test_after_staff_change_an_email_in_the_admin_the_command_lets_the_person_in():
    """Migrated (old@ unconfirmed primary), then staff corrected the email field to new@.
    The command confirms new@; the person should then be able to log in with it."""
    user = plain_user("old@example.com", username="person")
    run_the_migration()
    user.email = "new@example.com"
    user.save()
    call_command("mark_email_verified", "new@example.com", stdout=StringIO())
    assert log_in(Client(), email="new@example.com").url == ACCOUNT_PAGE
    primary = user.emailaddress_set.get(primary=True)
    user.refresh_from_db()
    assert primary.email == user.email


@pytest.mark.django_db(transaction=True)
def test_the_admin_sends_nothing_for_an_address_another_account_has_confirmed(
    admin_with_email_on_add, ada
):
    response = add_in_admin(admin_with_email_on_add, "Ada@Example.com", username="ada2")
    assert response.status_code == 302, response.content
    assert not [m for m in mail.outbox if "created for you" in m.subject]
    page = admin_with_email_on_add.get(response.url).content.decode()
    assert "No email was sent: another account has" in page


@pytest.mark.django_db(transaction=True)
def test_the_admin_tells_staff_the_link_was_sent(admin_with_email_on_add):
    response = add_in_admin(admin_with_email_on_add, "carol@example.com")
    page = admin_with_email_on_add.get(response.url).content.decode()
    assert "A link to choose a password was emailed to carol@example.com." in page
