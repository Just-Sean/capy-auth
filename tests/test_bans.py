"""The ban list: a banned address can't sign up or be added, and the pages don't show
that it's banned (only its owner is told, by email); attempts are recorded for staff;
banning suspends accounts and lifting reactivates them; the admin pages need permission
to change accounts; capy_auth.E005 stops a site without the signup check."""

import logging

import pytest
from allauth.account.models import EmailAddress
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.messages.storage.fallback import FallbackStorage
from django.core import mail
from django.test import Client, RequestFactory
from django.urls import reverse

from capy_auth.account.adapter import AccountAdapter
from capy_auth.bans.checks import check_signup_form
from capy_auth.bans.forms import BanCheck
from capy_auth.bans.models import BannedEmail, BannedEmailAttempt, BannedSocialAccount
from capy_auth.bans.selectors import accounts_using
from capy_auth.bans.services import lift_bans
from tests.accounts import ACCOUNT_PAGE, PASSWORD, RESET, log_in, sign_up, users_with_email
from tests.helpers import check_page

BANNED = "mallory@example.com"
BAN_SUBJECT = "This address can't be used for an account"
SUSPENDED_SUBJECT = "Your account has been suspended"
BANS = reverse("admin:capy_auth_bannedemail_changelist")
ADD_BAN = reverse("admin:capy_auth_bannedemail_add")
EMAIL_PAGE = reverse("account_email")


@pytest.fixture
def banned(db):
    return BannedEmail.objects.create(email=BANNED)


@pytest.fixture
def superuser_client(client):
    superuser = get_user_model().objects.create_superuser(
        username="admin", email="admin@example.com", password=PASSWORD
    )
    client.force_login(superuser)
    return client


def subjects():
    """Without the "[site] " prefix allauth adds."""
    return [message.subject.split("] ", 1)[-1] for message in mail.outbox]


def ban_in_admin(client, email):
    return client.post(ADD_BAN, {"email": email, "reason": ""})


# --- Signup -------------------------------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize("typed", [BANNED, " Mallory@Example.COM "])
def test_a_banned_signup_looks_like_any_other_and_creates_no_one(banned, typed):
    new = sign_up(Client(), email="eve@example.com")
    mail.outbox.clear()
    attempt = sign_up(Client(), email=typed)
    assert attempt.status_code == new.status_code == 302
    assert attempt.url == new.url  # the same "enter the code" page
    assert not users_with_email(BANNED).exists()
    assert subjects() == [BAN_SUBJECT]
    assert [message.to for message in mail.outbox] == [[BANNED]]


@pytest.mark.django_db
def test_the_ban_notice_carries_no_code_or_link(banned):
    sign_up(Client(), email=BANNED)
    body = mail.outbox[0].body
    assert "http" not in body.split("Thank you for using")[0]
    assert "can't be used for an account" in body


@pytest.mark.django_db
def test_a_signup_attempt_is_recorded_and_logged_without_the_address(banned, caplog):
    with caplog.at_level(logging.WARNING, logger="capy_auth"):
        sign_up(Client(REMOTE_ADDR="203.0.113.9"), email=BANNED)
    attempt = BannedEmailAttempt.objects.get()
    assert (attempt.email, attempt.kind, attempt.account) == (BANNED, "signup", None)
    assert attempt.ip_address == "203.0.113.9"
    assert "A banned email address was tried (signup)" in caplog.text
    assert BANNED not in caplog.text


@pytest.mark.django_db
def test_other_signups_arent_recorded(banned):
    sign_up(Client(), email="eve@example.com")
    assert not BannedEmailAttempt.objects.exists()


# --- Adding an address to an account -------------------------------------------------------


def add_email(client, email):
    return client.post(EMAIL_PAGE, {"email": email, "action_add": ""})


def logged_in_and_confirmed():
    """Ada, logged in, who has just typed her password again (adding an address asks
    for it: ACCOUNT_REAUTHENTICATION_REQUIRED)."""
    client = Client()
    log_in(client)
    client.post(reverse("account_reauthenticate"), {"password": PASSWORD})
    return client


@pytest.mark.django_db
def test_adding_a_banned_address_looks_normal_sends_no_code_and_is_flagged(ada, banned):
    normal_client, client = logged_in_and_confirmed(), logged_in_and_confirmed()
    normal = add_email(normal_client, "ada.alt@example.com")
    mail.outbox.clear()
    attempt = add_email(client, BANNED)
    assert attempt.status_code == normal.status_code == 302
    assert attempt.url == normal.url
    assert subjects() == [BAN_SUBJECT]
    assert not EmailAddress.objects.filter(email=BANNED).exists()
    flagged = BannedEmailAttempt.objects.get()
    assert (flagged.kind, flagged.account) == ("add_email", ada)


@pytest.mark.django_db
def test_a_banned_address_is_never_confirmed(ada, banned):
    request = RequestFactory().post("/")
    request.session = {}
    request._messages = FallbackStorage(request)
    address = EmailAddress(user=ada, email=BANNED)
    assert AccountAdapter().confirm_email(request, address) is False
    assert not EmailAddress.objects.filter(email=BANNED).exists()


@pytest.mark.django_db
def test_a_reset_for_a_banned_address_gets_the_ban_notice(banned):
    assert Client().post(RESET, {"email": BANNED}).status_code == 302
    assert subjects() == [BAN_SUBJECT]


# --- Banning and lifting in the admin --------------------------------------------------


@pytest.fixture
def mallory(db):
    user = get_user_model().objects.create_user(
        username="mallory", email="mallory.main@example.com", password=PASSWORD
    )
    EmailAddress.objects.create(user=user, email=user.email, primary=True, verified=True)
    EmailAddress.objects.create(user=user, email=BANNED, verified=True)
    return user


@pytest.mark.django_db
def test_banning_suspends_the_account_ends_its_session_and_emails_it(superuser_client, mallory):
    logged_in = Client()
    log_in(logged_in, email=mallory.email)
    assert logged_in.get(ACCOUNT_PAGE).status_code == 200
    mail.outbox.clear()
    response = ban_in_admin(superuser_client, " Mallory@Example.com")
    assert response.status_code == 302
    mallory.refresh_from_db()
    assert not mallory.is_active
    ban = BannedEmail.objects.get()
    assert ban.email == BANNED
    assert list(ban.suspended_accounts.all()) == [mallory]
    assert subjects() == [SUSPENDED_SUBJECT]
    assert mail.outbox[0].to == [mallory.email]
    assert logged_in.get(ACCOUNT_PAGE).status_code == 302  # signed out
    assert get_user_model().objects.filter(pk=mallory.pk).exists()  # never deleted


@pytest.mark.django_db
def test_an_unconfirmed_address_doesnt_suspend_its_account(superuser_client, ada):
    EmailAddress.objects.create(user=ada, email=BANNED, verified=False)
    ban_in_admin(superuser_client, BANNED)
    ada.refresh_from_db()
    assert ada.is_active


@pytest.mark.django_db
def test_the_same_address_cant_be_banned_twice_in_other_capitals(superuser_client, banned):
    response = superuser_client.post(ADD_BAN, {"email": "MALLORY@example.com", "reason": ""})
    assert response.status_code == 200
    assert BannedEmail.objects.count() == 1


@pytest.mark.django_db
def test_a_suspended_account_signing_in_sees_a_suspended_page(superuser_client, mallory):
    ban_in_admin(superuser_client, BANNED)
    client = Client()
    response = log_in(client, email=mallory.email)
    assert response.status_code == 302
    page = check_page(client.get(response.url))
    assert "This account has been suspended" in page
    wrong = log_in(Client(), email=mallory.email, password=PASSWORD + "-wrong")
    assert "suspended" not in wrong.content.decode()  # only the right password shows it


@pytest.mark.django_db
def test_lifting_reactivates_only_accounts_no_other_ban_holds(superuser_client, mallory, ada):
    ban_in_admin(superuser_client, BANNED)
    ban_in_admin(superuser_client, "mallory.main@example.com")
    other = BannedEmail.objects.create(email="other@example.com")
    other.suspended_accounts.add(ada)
    ada.is_active = False
    ada.save()
    first = BannedEmail.objects.get(email=BANNED)  # both bans hold mallory

    assert lift_bans(BannedEmail.objects.filter(pk=first.pk)) == 0
    assert not get_user_model().objects.get(pk=mallory.pk).is_active

    response = superuser_client.post(
        BANS,
        {
            "action": "lift_and_reactivate",
            "_selected_action": list(BannedEmail.objects.values_list("pk", flat=True)),
        },
    )
    assert response.status_code == 302
    assert not BannedEmail.objects.exists()
    assert get_user_model().objects.get(pk=mallory.pk).is_active
    assert get_user_model().objects.get(pk=ada.pk).is_active
    assert log_in(Client(), email=mallory.email).url == ACCOUNT_PAGE


@pytest.mark.django_db
def test_deleting_a_ban_lifts_it_without_reactivating(superuser_client, mallory):
    ban_in_admin(superuser_client, BANNED)
    ban = BannedEmail.objects.get()
    delete = reverse("admin:capy_auth_bannedemail_delete", args=[ban.pk])
    assert superuser_client.post(delete, {"post": "yes"}).status_code == 302
    assert not BannedEmail.objects.exists()
    mallory.refresh_from_db()
    assert not mallory.is_active


# --- Admin permissions ---------------------------------------------------------------------


def staff_client(*codenames):
    staff = get_user_model().objects.create_user(
        username="staff", email="staff@example.com", password=PASSWORD, is_staff=True
    )
    staff.user_permissions.add(*Permission.objects.filter(codename__in=codenames))
    client = Client()
    client.force_login(staff)
    return client


BAN_PERMISSIONS = (
    "view_bannedemail",
    "add_bannedemail",
    "change_bannedemail",
    "delete_bannedemail",
)


@pytest.mark.django_db
def test_managing_bans_needs_permission_to_change_accounts(banned):
    without = staff_client(*BAN_PERMISSIONS)
    assert without.get(ADD_BAN).status_code == 403
    assert without.get(BANS).status_code == 200  # can still look


@pytest.mark.django_db
def test_staff_who_can_change_accounts_can_ban():
    client = staff_client(*BAN_PERMISSIONS, "change_user", "change_emailuser")
    assert client.get(ADD_BAN).status_code == 200


@pytest.mark.django_db
def test_attempts_are_read_only_and_social_bans_can_be_added(superuser_client, banned):
    sign_up(Client(), email=BANNED)
    attempt = BannedEmailAttempt.objects.get()
    assert (
        superuser_client.get(reverse("admin:capy_auth_bannedemailattempt_add")).status_code == 403
    )
    change = reverse("admin:capy_auth_bannedemailattempt_change", args=[attempt.pk])
    page = superuser_client.get(change).content.decode()
    assert 'name="_save"' not in page
    response = superuser_client.post(
        reverse("admin:capy_auth_bannedsocialaccount_add"),
        {"provider": "google", "uid": "1234", "reason": ""},
    )
    assert response.status_code == 302
    assert str(BannedSocialAccount.objects.get()) == "google: 1234"


@pytest.mark.django_db
def test_admin_lists_open(superuser_client, banned):
    sign_up(Client(), email=BANNED)
    for name in ("bannedemail", "bannedsocialaccount", "bannedemailattempt"):
        assert (
            superuser_client.get(reverse(f"admin:capy_auth_{name}_changelist")).status_code == 200
        )


# --- The startup check -------------------------------------------------------------------


class OwnSignupForm:
    pass


@pytest.mark.parametrize(
    ("setting", "errors"),
    [
        ("capy_auth.bans.forms.BanCheck", []),
        ("tests.test_bans.ProjectSignupForm", []),
        ("tests.test_bans.OwnSignupForm", ["capy_auth.E005"]),
        ("tests.no_such_module.Form", ["capy_auth.E005"]),
        ("tests.test_bans.BAN_SUBJECT", ["capy_auth.E005"]),
        ("", ["capy_auth.E005"]),
        (None, ["capy_auth.E005"]),
    ],
)
def test_a_site_without_the_ban_check_at_signup_is_stopped(settings, setting, errors):
    settings.ACCOUNT_SIGNUP_FORM_CLASS = setting
    assert [error.id for error in check_signup_form(None)] == errors


class ProjectSignupForm(BanCheck):
    """A project's own signup form, based on BanCheck."""


@pytest.mark.django_db
def test_without_an_email_field_accounts_are_found_by_confirmed_address(settings, mallory, ada):
    settings.ACCOUNT_USER_MODEL_EMAIL_FIELD = None
    assert list(accounts_using(" MALLORY@example.com")) == [mallory]
    ada.emailaddress_set.all().delete()
    assert list(accounts_using(ada.email)) == []
