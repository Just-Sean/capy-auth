"""Managing email addresses on allauth's page; existing users' addresses added by a
migration; confirming one by hand (mark_email_verified); and the "choose your password"
email for accounts staff create in the admin."""

import importlib
from io import StringIO
from types import SimpleNamespace

import pytest
from allauth.account.models import EmailAddress
from allauth.core import context
from django.apps import apps
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.core import mail
from django.core.management import CommandError, call_command
from django.db import IntegrityError, connection
from django.test import Client, RequestFactory
from django.urls import resolve, reverse

from capy_auth.account import services
from capy_auth.account.receivers import is_the_user_admins_add_page
from capy_auth.account.services import link_lifetime, send_account_created_email
from capy_auth.bans.models import BannedEmail
from tests.accounts import ACCOUNT_PAGE, PASSWORD, code_from, log_in
from tests.helpers import check_page

EMAIL_PAGE = reverse("account_email")
existing_users = importlib.import_module("capy_auth.migrations.0004_existing_users_email_addresses")


def is_djangos_user_model():
    """The stand-in project's other user model (capy-project's) keeps emails unique and
    has no admin."""
    return get_user_model()._meta.label == "auth.User"


def subjects():
    return [message.subject.split("] ", 1)[-1] for message in mail.outbox]


def user_without_address(email="root@example.com", **extra):
    """An account made before capy-auth (createsuperuser, the admin, older data): it
    isn't in allauth's list of addresses."""
    return get_user_model().objects.create_user(
        username=email.split("@")[0] or "nobody", email=email, password=PASSWORD, **extra
    )


def logged_in_and_confirmed():
    """Ada, logged in, who has just typed her password again (the email page asks for
    it before a change: ACCOUNT_REAUTHENTICATION_REQUIRED)."""
    client = Client()
    log_in(client)
    client.post(reverse("account_reauthenticate"), {"password": PASSWORD})
    return client


# --- The email page -------------------------------------------------------------------------


@pytest.mark.django_db
def test_the_email_page_lists_the_accounts_addresses_in_the_layout(ada):
    client = Client()
    log_in(client)
    page = check_page(client.get(EMAIL_PAGE))
    assert "ada@example.com" in page


@pytest.mark.django_db
def test_the_email_page_wraps_groups_and_explains_its_buttons(ada):
    EmailAddress.objects.create(user=ada, email="ada.work@example.com", verified=False)
    client = Client()
    log_in(client)
    page = check_page(client.get(EMAIL_PAGE))
    assert '<legend class="fieldset-legend">Choose an address</legend>' in page
    assert page.count('<span class="break-all">') == 2  # long addresses wrap
    assert "Main address" in page and "Not confirmed yet" in page and "Confirmed" in page
    assert page.count('aria-describedby="email-actions-help"') == 3
    assert 'id="email-actions-help"' in page
    assert f'href="{ACCOUNT_PAGE}"' in page  # back to "Your account"


@pytest.mark.django_db
def test_after_choosing_a_password_the_next_step_is_signing_in():
    page = check_page(Client().get(reverse("account_reset_password_from_key_done")))
    assert "Your password is saved." in page
    assert f'href="{reverse("account_login")}"' in page


@pytest.mark.django_db
def test_an_address_is_added_once_its_code_is_entered(ada):
    client = logged_in_and_confirmed()
    response = client.post(EMAIL_PAGE, {"email": "Ada.Work@Example.com", "action_add": ""})
    assert not EmailAddress.objects.filter(email="ada.work@example.com").exists()
    client.post(response.url, {"code": code_from(mail.outbox[-1])})
    address = EmailAddress.objects.get(email="ada.work@example.com")
    assert (address.user, address.verified, address.primary) == (ada, True, False)


@pytest.mark.django_db
def test_a_confirmed_address_can_be_made_primary_and_the_old_one_removed(ada):
    EmailAddress.objects.create(user=ada, email="ada.work@example.com", verified=True)
    client = logged_in_and_confirmed()
    client.post(EMAIL_PAGE, {"email": "ada.work@example.com", "action_primary": ""})
    ada.refresh_from_db()
    assert ada.email == "ada.work@example.com"
    assert EmailAddress.objects.get(email="ada.work@example.com").primary
    client.post(EMAIL_PAGE, {"email": "ada@example.com", "action_remove": ""})
    assert list(ada.emailaddress_set.values_list("email", flat=True)) == ["ada.work@example.com"]
    assert subjects() == ["Email Changed", "Email Removed"]  # allauth tells the owner


@pytest.mark.django_db
def test_the_primary_address_cant_be_removed(ada):
    client = logged_in_and_confirmed()
    client.post(EMAIL_PAGE, {"email": "ada@example.com", "action_remove": ""})
    assert ada.emailaddress_set.filter(email="ada@example.com").exists()


@pytest.mark.django_db
def test_changes_ask_for_the_password_again(ada):
    client = Client()
    log_in(client)
    response = client.post(EMAIL_PAGE, {"email": "ada.work@example.com", "action_add": ""})
    assert response.url.startswith(reverse("account_reauthenticate"))


# --- Existing users ------------------------------------------------------------------------


def run_the_migration():
    existing_users.add_missing_addresses(apps, SimpleNamespace(connection=connection))


@pytest.mark.django_db
def test_existing_users_get_their_email_as_an_unconfirmed_primary_address(ada, monkeypatch):
    monkeypatch.setattr(existing_users, "BATCH_SIZE", 2)  # several batches
    roots = [user_without_address(f"Root{n}@Example.com") for n in range(5)]
    no_email = user_without_address("", is_staff=True) if is_djangos_user_model() else None
    run_the_migration()
    for root in roots:
        address = root.emailaddress_set.get()
        assert (address.email, address.primary, address.verified) == (
            root.email.lower(),
            True,
            False,
        )
    assert list(ada.emailaddress_set.values_list("verified", flat=True)) == [True]  # untouched
    if no_email is not None:
        assert not no_email.emailaddress_set.exists()
    run_the_migration()  # running again adds nothing
    assert EmailAddress.objects.count() == 6


@pytest.mark.django_db
def test_without_an_email_field_the_migration_does_nothing(settings):
    settings.ACCOUNT_USER_MODEL_EMAIL_FIELD = None
    user_without_address()
    run_the_migration()
    assert not EmailAddress.objects.exists()


@pytest.mark.django_db
def test_an_existing_superuser_is_asked_for_a_code_and_the_command_lets_them_in():
    root = get_user_model().objects.create_superuser(
        username="root", email="root@example.com", password=PASSWORD
    )
    run_the_migration()
    response = log_in(Client(), email="root@example.com")
    assert response.url != ACCOUNT_PAGE  # the code page
    assert mail.outbox[-1].to == ["root@example.com"]
    out = StringIO()
    call_command("mark_email_verified", " Root@Example.com ", stdout=out)
    assert "Confirmed root@example.com" in out.getvalue()
    assert root.emailaddress_set.get().verified
    assert log_in(Client(), email="root@example.com").url == ACCOUNT_PAGE


# --- mark_email_verified --------------------------------------------------------------------


@pytest.mark.django_db
def test_the_command_adds_the_address_when_allauth_has_none():
    root = user_without_address()
    call_command("mark_email_verified", "root@example.com", stdout=StringIO())
    address = root.emailaddress_set.get()
    assert (address.email, address.verified, address.primary) == ("root@example.com", True, True)


@pytest.mark.django_db
def test_the_command_keeps_the_existing_primary(ada):
    EmailAddress.objects.create(user=ada, email="ada.work@example.com", verified=False)
    call_command("mark_email_verified", "ada.work@example.com", stdout=StringIO())
    work = EmailAddress.objects.get(email="ada.work@example.com")
    assert work.verified and not work.primary


@pytest.mark.django_db
def test_the_command_refuses_unknown_and_banned_addresses(ada):
    with pytest.raises(CommandError, match="No account uses nobody@example.com"):
        call_command("mark_email_verified", "nobody@example.com")
    BannedEmail.objects.create(email="ada@example.com")
    with pytest.raises(CommandError, match="on the ban list"):
        call_command("mark_email_verified", "ada@example.com")


@pytest.mark.django_db
def test_the_command_refuses_an_address_two_accounts_use():
    if not is_djangos_user_model():
        pytest.skip("capy-project's user model keeps emails unique")
    user_without_address("twin@example.com")
    get_user_model().objects.create_user(username="twin2", email="twin@example.com")
    with pytest.raises(CommandError, match="More than one account uses twin@example.com"):
        call_command("mark_email_verified", "twin@example.com")


# --- Accounts created by staff ----------------------------------------------------------------


def request_on(match, user):
    request = RequestFactory().post("/")
    request.resolver_match = match
    request.user = user
    return request


@pytest.mark.django_db
def test_only_staff_on_the_user_admins_add_page_trigger_the_email(ada):
    options = get_user_model()._meta
    add_page = SimpleNamespace(
        app_names=["admin"], url_name=f"{options.app_label}_{options.model_name}_add"
    )
    staff = get_user_model().objects.create_user(
        username="staff", email="s@example.com", is_staff=True
    )
    assert is_the_user_admins_add_page(request_on(add_page, staff))
    assert not is_the_user_admins_add_page(request_on(add_page, ada))  # not staff
    assert not is_the_user_admins_add_page(request_on(add_page, AnonymousUser()))
    login_page = resolve(reverse("admin:login"))  # a login system may create users here
    assert not is_the_user_admins_add_page(request_on(login_page, staff))
    assert not is_the_user_admins_add_page(request_on(resolve(reverse("admin:index")), staff))
    assert not is_the_user_admins_add_page(None)


@pytest.mark.django_db
def test_accounts_made_elsewhere_arent_emailed(django_capture_on_commit_callbacks):
    with django_capture_on_commit_callbacks(execute=True):
        user_without_address("shell@example.com")  # the shell, createsuperuser
        with context.request_context(RequestFactory().get("/")):
            user_without_address("page@example.com")  # not an admin page
    assert mail.outbox == []


@pytest.mark.django_db
def test_an_account_without_an_email_isnt_emailed():
    if not is_djangos_user_model():
        pytest.skip("capy-project's user model needs an email")
    with context.request_context(RequestFactory().get("/")):
        assert send_account_created_email(user_without_address("")) is False
    assert mail.outbox == []


@pytest.mark.django_db
def test_django_s_own_add_user_page_sends_nothing(
    superuser_client_factory, django_capture_on_commit_callbacks
):
    """Django's own user admin doesn't ask for an email when adding, so nothing is sent
    (capy-project's admin asks for one)."""
    if not is_djangos_user_model():
        pytest.skip("capy-project's user model has no admin in the stand-in project")
    client = superuser_client_factory()
    with django_capture_on_commit_callbacks(execute=True):
        response = client.post(
            reverse("admin:auth_user_add"),
            {
                "username": "dave",
                "usable_password": "true",
                "password1": PASSWORD,
                "password2": PASSWORD,
            },
        )
    assert response.status_code == 302
    assert get_user_model().objects.filter(username="dave").exists()
    assert mail.outbox == []


@pytest.fixture
def superuser_client_factory(db):
    def make():
        superuser = get_user_model().objects.create_superuser(
            username="admin", email="admin@example.com", password=PASSWORD
        )
        client = Client()
        client.force_login(superuser)
        return client

    return make


@pytest.mark.django_db
def test_without_an_email_field_the_command_finds_allauths_addresses(settings, ada):
    settings.ACCOUNT_USER_MODEL_EMAIL_FIELD = None
    EmailAddress.objects.create(user=ada, email="ada.work@example.com", verified=False)
    call_command("mark_email_verified", "ada.work@example.com", stdout=StringIO())
    assert EmailAddress.objects.get(email="ada.work@example.com").verified
    with pytest.raises(CommandError, match="No account uses"):
        call_command("mark_email_verified", "nobody@example.com")


@pytest.mark.parametrize(
    ("seconds", "words"), [(3600, "1 hour"), (259200, "72 hours"), (900, "15 minutes")]
)
def test_the_email_says_how_long_the_link_works(settings, seconds, words):
    settings.PASSWORD_RESET_TIMEOUT = seconds
    assert link_lifetime() == words


@pytest.mark.django_db
def test_a_clash_while_confirming_gives_a_clear_message(ada, monkeypatch):
    def clash(user, email):
        raise IntegrityError("unique_verified_email")

    monkeypatch.setattr(services, "confirm_on_account", clash)
    with pytest.raises(CommandError, match="couldn't be confirmed"):
        call_command("mark_email_verified", "ada@example.com")
