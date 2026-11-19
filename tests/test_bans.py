"""The ban list: a banned address can't sign up or be added, and the pages don't show
that it's banned (only its owner is told, by email); real attempts are recorded for
staff; a banned address is never confirmed; banning suspends accounts and lifting
reactivates them; the admin pages need permission to change accounts; capy_auth.E005
stops a site without the signup check."""

import logging
import re

import pytest
from allauth.account.models import EmailAddress
from allauth.usersessions.models import UserSession
from django.apps import apps
from django.contrib.admin.models import CHANGE, DELETION, LogEntry
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.messages import get_messages
from django.contrib.messages.storage.fallback import FallbackStorage
from django.core import mail
from django.db import transaction
from django.test import Client, RequestFactory
from django.urls import reverse

from capy_auth.account.adapter import EMAIL_NOT_CONFIRMED, AccountAdapter
from capy_auth.bans.checks import check_signup_form
from capy_auth.bans.forms import BanCheck
from capy_auth.bans.models import (
    BannedEmail,
    BannedEmailAttempt,
    BannedSocialAccount,
    normalize_email,
)
from capy_auth.bans.selectors import accounts_using, is_banned_email
from capy_auth.bans.services import client_ip, lift_bans, send_restored_notices, suspend_accounts
from tests.accounts import (
    ACCOUNT_PAGE,
    NEW_PASSWORD,
    PASSWORD,
    RESET,
    code_from,
    log_in,
    sign_up,
    users_with_email,
)
from tests.helpers import check_page
from tests.staff import two_step_client

BANNED = "mallory@example.com"
BAN_SUBJECT = "This address can't be used for an account"
SUSPENDED_SUBJECT = "Your account has been suspended"
BANS = reverse("admin:capy_auth_bannedemail_changelist")
ADD_BAN = reverse("admin:capy_auth_bannedemail_add")
ATTEMPTS = reverse("admin:capy_auth_bannedemailattempt_changelist")
EMAIL_PAGE = reverse("account_email")
BAN_PERMISSIONS = (
    "view_bannedemail",
    "add_bannedemail",
    "change_bannedemail",
    "delete_bannedemail",
)
# The user model's permission, under both test user models' names.
CHANGE_ACCOUNTS = ("change_user", "change_emailuser")
VIEW_ACCOUNTS = ("view_user", "view_emailuser")


@pytest.fixture
def banned(db):
    return BannedEmail.objects.create(email=BANNED)


@pytest.fixture
def superuser_client(client):
    superuser = get_user_model().objects.create_superuser(
        username="admin", email="admin@example.com", password=PASSWORD
    )
    return two_step_client(superuser, client)


@pytest.fixture
def mallory(db):
    """An account whose second, confirmed address gets banned."""
    user = get_user_model().objects.create_user(
        username="mallory", email="mallory.main@example.com", password=PASSWORD
    )
    EmailAddress.objects.create(user=user, email=user.email, primary=True, verified=True)
    EmailAddress.objects.create(user=user, email=BANNED, verified=True)
    return user


@pytest.fixture
def ban_in_admin(superuser_client, django_capture_on_commit_callbacks):
    """Bans an address on the admin's add page, running what waits for the save (the
    suspension emails)."""

    def ban(email, client=superuser_client):
        with django_capture_on_commit_callbacks(execute=True):
            return client.post(ADD_BAN, {"email": email, "reason": ""})

    return ban


def subjects():
    """Without the "[site] " prefix allauth adds."""
    return [message.subject.split("] ", 1)[-1] for message in mail.outbox]


def staff_client(*codenames):
    staff = get_user_model().objects.create_user(
        username="staff", email="staff@example.com", password=PASSWORD, is_staff=True
    )
    staff.user_permissions.add(*Permission.objects.filter(codename__in=codenames))
    return two_step_client(staff)


def lift(client, *bans):
    return client.post(
        BANS, {"action": "lift_and_reactivate", "_selected_action": [ban.pk for ban in bans]}
    )


def choose_new_password(client, message):
    """Follows the email's one-time link and chooses NEW_PASSWORD."""
    link = message.body.split("http://testserver", 1)[1].split()[0]
    page = client.get(link, follow=True)
    form_url = page.redirect_chain[-1][0]
    return client.post(form_url, {"password1": NEW_PASSWORD, "password2": NEW_PASSWORD})


def is_active(user):
    user.refresh_from_db()
    return user.is_active


def normalized_page(response, email):
    """The page without what legitimately differs (the address typed, tokens, nonces),
    so two pages can be compared."""
    page = response.content.decode().replace(email, "EMAIL")
    page = re.sub(r'name="csrfmiddlewaretoken" value="[^"]+"', "CSRF", page)
    return re.sub(r'nonce="[^"]+"', "NONCE", page)


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
def test_the_code_page_after_a_banned_signup_matches_a_normal_one(banned):
    normal_client, banned_client = Client(), Client()
    normal = sign_up(normal_client, email="eve@example.com")
    attempt = sign_up(banned_client, email=BANNED)
    normal_page = normal_client.get(normal.url)
    banned_page = banned_client.get(attempt.url)
    assert banned_page.status_code == normal_page.status_code == 200
    assert normalized_page(banned_page, BANNED) == normalized_page(normal_page, "eve@example.com")


@pytest.mark.django_db
def test_a_wrong_code_after_a_banned_signup_looks_like_a_normal_one(banned):
    normal_client, banned_client = Client(), Client()
    normal = sign_up(normal_client, email="eve@example.com")
    attempt = sign_up(banned_client, email=BANNED)
    normal_wrong = normal_client.post(normal.url, {"code": "AAAA-AAAA"})
    banned_wrong = banned_client.post(attempt.url, {"code": "AAAA-AAAA"})
    assert banned_wrong.status_code == normal_wrong.status_code
    assert normalized_page(banned_wrong, BANNED) == normalized_page(normal_wrong, "eve@example.com")


@pytest.mark.django_db
def test_resending_after_a_banned_signup_looks_normal_and_sends_no_code(banned):
    normal_client, banned_client = Client(), Client()
    normal = sign_up(normal_client, email="eve@example.com")
    attempt = sign_up(banned_client, email=BANNED)
    mail.outbox.clear()
    normal_resend = normal_client.post(normal.url, {"action": "resend"}, follow=True)
    banned_resend = banned_client.post(attempt.url, {"action": "resend"}, follow=True)
    assert banned_resend.redirect_chain == normal_resend.redirect_chain
    assert normalized_page(banned_resend, BANNED) == normalized_page(
        normal_resend, "eve@example.com"
    )
    assert [BANNED] not in [message.to for message in mail.outbox]


@pytest.mark.django_db
def test_the_ban_notice_carries_no_code_link_or_thank_you(banned):
    sign_up(Client(), email=BANNED)
    body = mail.outbox[0].body
    assert "can't be used for an account" in body
    assert "http" not in body
    assert "Thank you" not in body


@pytest.mark.django_db
def test_a_signup_attempt_is_recorded_once_and_logged_without_the_address(banned, caplog):
    with caplog.at_level(logging.WARNING, logger="capy_auth"):
        sign_up(Client(REMOTE_ADDR="203.0.113.9"), email=BANNED)
    attempt = BannedEmailAttempt.objects.get()
    assert (attempt.email, attempt.kind, attempt.account) == (BANNED, "signup", None)
    assert attempt.ip_address == "203.0.113.9"
    assert "A banned email address was tried (signup)" in caplog.text
    assert BANNED not in caplog.text


@pytest.mark.django_db
def test_a_signup_with_another_mistake_isnt_recorded_until_its_fixed(banned):
    page = sign_up(Client(), email=BANNED, password=PASSWORD[:4])
    assert page.status_code == 200  # the password error, as for anyone
    assert not BannedEmailAttempt.objects.exists()


@pytest.mark.django_db
def test_other_signups_arent_recorded(banned):
    sign_up(Client(), email="eve@example.com")
    assert not BannedEmailAttempt.objects.exists()


# --- Addresses written differently ----------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize(
    "typed", ["MALLORY@EXAMPLE.COM", "\tmallory@example.com\n", " Mallory@Example.com "]
)
def test_variants_of_a_banned_address_are_caught(banned, typed):
    assert is_banned_email(typed)


@pytest.mark.django_db
def test_a_ban_typed_in_capitals_is_stored_normalized_and_matches():
    BannedEmail.objects.create(email="  MALLORY@Example.COM ")
    assert BannedEmail.objects.get().email == BANNED
    sign_up(Client(), email=BANNED)
    assert not users_with_email(BANNED).exists()


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("ban", "typed"),
    [
        ("mallory@xn--bcher-kva.example", "mallory@bücher.example"),
        ("mallory@bücher.example", "Mallory@XN--BCHER-KVA.example"),
    ],
)
def test_an_international_domain_matches_its_punycode_form(ban, typed):
    BannedEmail.objects.create(email=ban)
    assert is_banned_email(typed)


def test_an_address_that_cant_be_encoded_is_kept_as_typed():
    assert normalize_email(" A@" + "x" * 70 + ".example ") == "a@" + "x" * 70 + ".example"
    assert normalize_email(None) == ""


@pytest.mark.django_db
def test_plus_tags_are_different_addresses(banned):
    assert not is_banned_email("mallory+x@example.com")  # README: only exact addresses


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
    assert normalized_page(client.get(attempt.url), BANNED) == normalized_page(
        normal_client.get(normal.url), "ada.alt@example.com"
    )
    assert subjects() == [BAN_SUBJECT]
    assert not EmailAddress.objects.filter(email=BANNED).exists()
    flagged = BannedEmailAttempt.objects.get()
    assert (flagged.kind, flagged.account) == ("add_email", ada)


@pytest.mark.django_db
def test_a_banned_address_is_never_confirmed_and_the_message_doesnt_say_why(ada, banned):
    request = RequestFactory().post("/")
    request.session = {}
    request._messages = FallbackStorage(request)
    address = EmailAddress(user=ada, email=BANNED)
    assert AccountAdapter().confirm_email(request, address) is False
    assert not address.verified
    assert [str(message) for message in get_messages(request)] == [str(EMAIL_NOT_CONFIRMED)]


@pytest.mark.django_db
def test_a_code_sent_before_the_ban_cant_confirm_the_address_afterwards(ada):
    client = logged_in_and_confirmed()
    response = add_email(client, "late@example.com")
    code = code_from(mail.outbox[-1])
    BannedEmail.objects.create(email="late@example.com")
    client.post(response.url, {"code": code})
    assert not EmailAddress.objects.filter(email="late@example.com", verified=True).exists()


@pytest.mark.django_db
def test_a_signup_code_sent_before_the_ban_doesnt_let_the_account_in():
    client = Client()
    response = sign_up(client, email="late@example.com")
    code = code_from(mail.outbox[-1])
    BannedEmail.objects.create(email="late@example.com")
    client.post(response.url, {"code": code})
    assert client.get(ACCOUNT_PAGE).status_code == 302
    assert not EmailAddress.objects.filter(email="late@example.com", verified=True).exists()


@pytest.mark.django_db
def test_no_path_stores_a_banned_address_as_confirmed(ada, banned, superuser_client):
    """Whatever confirms it (a login or reset code sent before the ban, staff in the
    admin), the database keeps it unconfirmed."""
    address = EmailAddress.objects.create(user=ada, email=BANNED, verified=True)
    assert not EmailAddress.objects.get(pk=address.pk).verified
    superuser_client.post(
        reverse("admin:account_emailaddress_changelist"),
        {"action": "make_verified", "_selected_action": [address.pk]},
    )
    assert not EmailAddress.objects.get(pk=address.pk).verified


# --- Other forms that ask for an address -----------------------------------------------------


@pytest.mark.django_db
def test_a_reset_for_a_banned_address_gets_the_ban_notice_and_isnt_recorded(banned):
    assert Client().post(RESET, {"email": BANNED}).status_code == 302
    assert subjects() == [BAN_SUBJECT]
    assert not BannedEmailAttempt.objects.exists()


@pytest.mark.django_db
def test_a_signed_in_reset_isnt_recorded_against_the_account(ada, banned):
    client = Client()
    log_in(client)
    client.post(RESET, {"email": BANNED})
    assert not BannedEmailAttempt.objects.exists()


def test_an_unreadable_visitor_address_is_stored_as_unknown():
    request = RequestFactory().get("/", REMOTE_ADDR="")
    assert client_ip(request) is None
    assert client_ip(None) is None


# --- Banning in the admin -------------------------------------------------------------------


@pytest.mark.django_db
def test_banning_suspends_the_account_ends_its_session_and_emails_it(
    superuser_client, ban_in_admin, mallory, ada
):
    logged_in = Client()
    log_in(logged_in, email=mallory.email)
    assert logged_in.get(ACCOUNT_PAGE).status_code == 200
    mail.outbox.clear()
    response = ban_in_admin(" Mallory@Example.com")
    assert response.status_code == 302
    assert not is_active(mallory)
    assert is_active(ada)  # accounts not using the address are left alone
    ban = BannedEmail.objects.get()
    assert ban.email == BANNED
    assert list(ban.suspended_accounts.all()) == [mallory]
    assert subjects() == [SUSPENDED_SUBJECT]
    assert mail.outbox[0].to == [mallory.email]  # its main address
    assert "Thank you" not in mail.outbox[0].body
    assert logged_in.get(ACCOUNT_PAGE).status_code == 302  # signed out
    assert get_user_model().objects.filter(pk=mallory.pk).exists()  # never deleted


@pytest.mark.django_db
def test_the_suspension_email_reaches_a_banned_main_address(ban_in_admin, ada):
    ban_in_admin(ada.email)
    assert subjects() == [SUSPENDED_SUBJECT]
    assert mail.outbox[0].to == [ada.email]


@pytest.mark.django_db
def test_a_ban_that_matches_nobody_says_so(superuser_client, ban_in_admin):
    response = ban_in_admin("nobody@example.com")
    page = superuser_client.get(response.url).content.decode()
    assert "No account uses this address." in page
    assert mail.outbox == []


@pytest.mark.django_db
def test_no_email_is_sent_when_the_ban_isnt_saved(superuser_client, mallory):
    """The suspension email waits for the save; without it, nothing goes out."""
    superuser_client.post(ADD_BAN, {"email": BANNED, "reason": ""})  # never committed
    assert mail.outbox == []


@pytest.mark.django_db
def test_an_unconfirmed_address_doesnt_suspend_its_account(ban_in_admin, ada):
    EmailAddress.objects.create(user=ada, email=BANNED, verified=False)
    ban_in_admin(BANNED)
    assert is_active(ada)


@pytest.mark.django_db
def test_banning_an_address_two_accounts_use_suspends_both(ban_in_admin, mallory):
    if get_user_model().USERNAME_FIELD != "username":
        pytest.skip("the email user model keeps emails unique")
    other = get_user_model().objects.create_user(username="other", email=BANNED, password=PASSWORD)
    ban_in_admin(BANNED)
    assert not is_active(mallory) and not is_active(other)
    assert set(BannedEmail.objects.get().suspended_accounts.all()) == {mallory, other}


@pytest.mark.django_db
def test_the_same_address_cant_be_banned_twice_in_other_capitals(superuser_client, banned):
    response = superuser_client.post(ADD_BAN, {"email": "MALLORY@example.com", "reason": ""})
    assert response.status_code == 200
    assert BannedEmail.objects.count() == 1


@pytest.mark.django_db
def test_staff_cant_ban_their_own_address(superuser_client):
    response = superuser_client.post(ADD_BAN, {"email": " Admin@Example.com", "reason": ""})
    assert response.status_code == 200
    assert "one of your own addresses" in response.content.decode()
    assert not BannedEmail.objects.exists()
    assert superuser_client.get(BANS).status_code == 200


@pytest.mark.django_db
def test_staff_who_can_change_accounts_can_suspend_a_superuser_by_ban(
    superuser_client, ban_in_admin
):
    """Django lets the same staff untick "Active" on a superuser; a ban is no more."""
    boss = get_user_model().objects.get(is_superuser=True)
    staff = staff_client(*BAN_PERMISSIONS, *CHANGE_ACCOUNTS)
    assert ban_in_admin(boss.email, client=staff).status_code == 302
    assert not is_active(boss)


@pytest.mark.django_db
def test_editing_a_ban_changes_no_account_and_keeps_its_address(
    superuser_client, ban_in_admin, mallory, django_capture_on_commit_callbacks
):
    ban_in_admin(BANNED)
    mallory.is_active = True  # staff let her back in, by hand
    mallory.save()
    mail.outbox.clear()
    ban = BannedEmail.objects.get()
    change = reverse("admin:capy_auth_bannedemail_change", args=[ban.pk])
    with django_capture_on_commit_callbacks(execute=True):
        superuser_client.post(change, {"email": "someone.else@example.com", "reason": "spam"})
    ban.refresh_from_db()
    assert (ban.email, ban.reason) == (BANNED, "spam")  # the address can't be changed
    assert is_active(mallory)
    assert mail.outbox == []
    page = superuser_client.get(change).content.decode()
    assert "Deleting a ban keeps the accounts it suspended suspended" in page
    assert str(mallory) in page  # the accounts it suspended


@pytest.mark.django_db
def test_a_banned_account_cant_sign_in_and_one_suspended_by_hand_sees_why(
    ban_in_admin, mallory, ada
):
    ban_in_admin(BANNED)
    refused = log_in(Client(), email=mallory.email)
    assert refused.status_code == 200  # as for a wrong password: suspension removed it
    assert "suspended" not in refused.content.decode()  # the suspension email says why
    ada.is_active = False  # staff unticked "Active" by hand; the password still works
    ada.save()
    client = Client()
    response = log_in(client)
    assert response.status_code == 302
    page = check_page(client.get(response.url))
    assert "This account has been suspended" in page
    assert 'href="/"' in page
    wrong = log_in(Client(), password=PASSWORD + "-wrong")
    assert "suspended" not in wrong.content.decode()  # only the right password shows it


# --- Lifting --------------------------------------------------------------------------------


@pytest.mark.django_db
def test_lifting_reactivates_only_accounts_no_other_ban_holds_and_is_recorded(
    superuser_client, ban_in_admin, mallory, ada, django_capture_on_commit_callbacks
):
    ban_in_admin(BANNED)
    ban_in_admin("mallory.main@example.com")  # also holds mallory, already suspended
    first = BannedEmail.objects.get(email=BANNED)
    assert lift_bans(BannedEmail.objects.filter(pk=first.pk)) == []
    assert not is_active(mallory)

    ban_in_admin(ada.email)
    mail.outbox.clear()
    with django_capture_on_commit_callbacks(execute=True):
        response = lift(superuser_client, *BannedEmail.objects.all())
    assert response.status_code == 302
    assert not BannedEmail.objects.exists()
    assert is_active(mallory) and is_active(ada)
    assert subjects() == ["Your account has been restored"] * 2
    assert log_in(Client(), email=mallory.email).status_code == 200  # the old password is gone
    restored = next(m for m in mail.outbox if m.to == [mallory.email])
    choose_new_password(Client(), restored)
    assert log_in(Client(), email=mallory.email, password=NEW_PASSWORD).url == ACCOUNT_PAGE
    page = superuser_client.get(response.url).content.decode()
    assert (
        "2 bans lifted; 2 accounts reactivated and emailed a link to choose a new password." in page
    )
    assert LogEntry.objects.filter(action_flag=DELETION, object_repr=ada.email).exists()
    reactivated = LogEntry.objects.filter(action_flag=CHANGE).values_list("object_id", flat=True)
    assert set(reactivated) == {str(mallory.pk), str(ada.pk)}


@pytest.mark.django_db
def test_lifting_reactivates_when_another_ban_holds_nobody(ban_in_admin, mallory):
    BannedEmail.objects.create(email="nobody@example.com")
    ban_in_admin(BANNED)
    assert lift_bans(BannedEmail.objects.filter(email=BANNED)) == [mallory]
    assert is_active(mallory)


@pytest.mark.django_db
def test_lifting_leaves_an_account_staff_deactivated_by_hand(ban_in_admin, mallory):
    mallory.is_active = False
    mallory.save()
    ban_in_admin(BANNED)
    ban = BannedEmail.objects.get()
    assert list(ban.suspended_accounts.all()) == []
    assert lift_bans(BannedEmail.objects.all()) == []
    assert not is_active(mallory)


@pytest.mark.django_db
def test_deleting_a_ban_lifts_it_without_reactivating(superuser_client, ban_in_admin, mallory):
    ban_in_admin(BANNED)
    ban = BannedEmail.objects.get()
    delete = reverse("admin:capy_auth_bannedemail_delete", args=[ban.pk])
    assert superuser_client.post(delete, {"post": "yes"}).status_code == 302
    assert not BannedEmail.objects.exists()
    assert not is_active(mallory)


# --- Admin permissions ---------------------------------------------------------------------


@pytest.mark.django_db
def test_managing_bans_needs_permission_to_change_accounts(banned):
    without = staff_client(*BAN_PERMISSIONS, *VIEW_ACCOUNTS)
    assert without.get(ADD_BAN).status_code == 403
    assert without.get(BANS).status_code == 200  # can still look
    lift(without, banned)
    assert BannedEmail.objects.exists()


@pytest.mark.django_db
def test_looking_needs_permission_to_see_accounts(banned):
    sign_up(Client(), email=BANNED)
    without = staff_client("view_bannedemail", "view_bannedemailattempt")
    assert without.get(BANS).status_code == 403
    assert without.get(ATTEMPTS).status_code == 403


@pytest.mark.django_db
def test_staff_who_can_change_accounts_can_ban():
    client = staff_client(*BAN_PERMISSIONS, *CHANGE_ACCOUNTS)
    assert client.get(ADD_BAN).status_code == 200


@pytest.mark.django_db
def test_staff_without_account_permissions_cant_lift_delete_or_edit(ban_in_admin, mallory):
    ban_in_admin(BANNED)
    ban = BannedEmail.objects.get()
    staff = staff_client(*BAN_PERMISSIONS)
    lift(staff, ban)
    staff.post(BANS, {"action": "delete_selected", "_selected_action": [ban.pk], "post": "yes"})
    delete = reverse("admin:capy_auth_bannedemail_delete", args=[ban.pk])
    assert staff.post(delete, {"post": "yes"}).status_code == 403
    assert BannedEmail.objects.exists()
    assert not is_active(mallory)


@pytest.mark.django_db
def test_attempts_are_read_only_and_deleting_them_needs_account_permission(
    superuser_client, banned
):
    sign_up(Client(), email=BANNED)
    attempt = BannedEmailAttempt.objects.get()
    add = reverse("admin:capy_auth_bannedemailattempt_add")
    assert superuser_client.get(add).status_code == 403
    change = reverse("admin:capy_auth_bannedemailattempt_change", args=[attempt.pk])
    assert 'name="_save"' not in superuser_client.get(change).content.decode()
    assert superuser_client.post(change, {"email": "x@example.com"}).status_code == 403
    delete = reverse("admin:capy_auth_bannedemailattempt_delete", args=[attempt.pk])
    viewer = staff_client("view_bannedemailattempt", "delete_bannedemailattempt", *VIEW_ACCOUNTS)
    assert viewer.get(ATTEMPTS).status_code == 200
    assert viewer.post(delete, {"post": "yes"}).status_code == 403
    assert BannedEmailAttempt.objects.exists()


@pytest.mark.django_db
def test_social_bans_can_be_added_and_the_lists_open(superuser_client, banned):
    response = superuser_client.post(
        reverse("admin:capy_auth_bannedsocialaccount_add"),
        {"provider": "google", "uid": "1234", "reason": ""},
    )
    assert response.status_code == 302
    assert str(BannedSocialAccount.objects.get()) == "google: 1234"
    sign_up(Client(), email=BANNED)
    for name in ("bannedemail", "bannedsocialaccount", "bannedemailattempt"):
        assert (
            superuser_client.get(reverse(f"admin:capy_auth_{name}_changelist")).status_code == 200
        )


# --- Odds and ends --------------------------------------------------------------------------


@pytest.mark.django_db
def test_without_an_email_field_accounts_are_found_by_confirmed_address(settings, mallory, ada):
    settings.ACCOUNT_USER_MODEL_EMAIL_FIELD = None
    assert list(accounts_using(" MALLORY@example.com")) == [mallory]
    ada.emailaddress_set.all().delete()
    assert list(accounts_using(ada.email)) == []


class OwnSignupForm:
    pass


class ProjectSignupForm(BanCheck):
    """A project's own signup form, based on BanCheck."""


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


@pytest.mark.django_db
def test_lifting_a_ban_signs_nobody_back_in(superuser_client, ban_in_admin, mallory):
    browser = Client()
    log_in(browser, email=mallory.email)
    assert browser.get(ACCOUNT_PAGE).status_code == 200
    ban_in_admin(BANNED)
    assert not UserSession.objects.filter(user=mallory).exists()  # ended, not just refused
    lift(superuser_client, BannedEmail.objects.get())
    assert is_active(mallory)
    assert browser.get(ACCOUNT_PAGE).status_code == 302  # has to sign in again


@pytest.mark.django_db
def test_without_allauths_sessions_app_a_ban_still_works(monkeypatch, ban_in_admin, mallory):
    installed = apps.is_installed
    monkeypatch.setattr(
        apps, "is_installed", lambda name: name != "allauth.usersessions" and installed(name)
    )
    ban_in_admin(BANNED)
    assert not is_active(mallory)


@pytest.mark.django_db
def test_without_allauths_mfa_app_a_ban_still_works(monkeypatch, ban_in_admin, mallory):
    installed = apps.is_installed
    monkeypatch.setattr(
        apps, "is_installed", lambda name: name != "allauth.mfa" and installed(name)
    )
    ban_in_admin(BANNED)
    assert not is_active(mallory)


# --- Signed out everywhere ---------------------------------------------------------------


def browser_of(user, **extra):
    client = Client(**extra)
    log_in(client, email=user.email)
    assert client.get(ACCOUNT_PAGE).status_code == 200
    return client


def ban_and_lift(ban_in_admin, superuser_client):
    ban_in_admin(BANNED)
    lift(superuser_client, BannedEmail.objects.get())


@pytest.mark.django_db
def test_a_sign_in_nobody_recorded_isnt_signed_back_in(superuser_client, ban_in_admin, mallory):
    browser = Client(REMOTE_ADDR="")  # its address can't be read, so it isn't recorded
    browser.force_login(mallory)
    assert not UserSession.objects.filter(user=mallory).exists()
    ban_and_lift(ban_in_admin, superuser_client)
    assert is_active(mallory)
    assert browser.get(ACCOUNT_PAGE).status_code == 302


@pytest.mark.django_db
def test_a_session_from_before_recording_isnt_signed_back_in(
    superuser_client, ban_in_admin, mallory
):
    browser = browser_of(mallory)
    UserSession.objects.filter(user=mallory).delete()  # as on a site that just added it
    ban_and_lift(ban_in_admin, superuser_client)
    assert browser.get(ACCOUNT_PAGE).status_code == 302


@pytest.mark.django_db
def test_every_browser_and_an_admin_session_are_signed_out(superuser_client, ban_in_admin, mallory):
    browsers = [browser_of(mallory, HTTP_USER_AGENT=f"B{n}") for n in range(3)]
    mallory.is_staff = True
    mallory.save()
    admin = two_step_client(mallory)
    assert admin.get("/admin/").status_code == 200
    ban_and_lift(ban_in_admin, superuser_client)
    # Sent to sign in, signed out: not to two-step sign-in, as a signed-in staff
    # member without it would be (the ban removed it).
    sign_in = reverse("account_login")
    assert all(b.get(ACCOUNT_PAGE).url.startswith(sign_in) for b in browsers)
    assert admin.get(ACCOUNT_PAGE).url.startswith(sign_in)


@pytest.mark.django_db
def test_the_banning_staff_and_other_accounts_stay_signed_in(
    superuser_client, ban_in_admin, mallory, ada
):
    bystander = browser_of(ada)
    ban_and_lift(ban_in_admin, superuser_client)
    assert superuser_client.get("/admin/").status_code == 200
    assert bystander.get(ACCOUNT_PAGE).status_code == 200
    assert UserSession.objects.filter(user=ada).exists()


@pytest.mark.django_db
def test_a_second_ban_and_lifting_both_signs_nobody_back_in(
    superuser_client, ban_in_admin, mallory
):
    browser = browser_of(mallory)
    ban_in_admin(BANNED)
    ban_in_admin(mallory.email)  # the account's other address; already suspended
    lift(superuser_client, *BannedEmail.objects.all())
    assert is_active(mallory)
    assert browser.get(ACCOUNT_PAGE).status_code == 302


@pytest.mark.django_db
@pytest.mark.parametrize(
    "engine",
    ["django.contrib.sessions.backends.cache", "django.contrib.sessions.backends.cached_db"],
)
def test_sessions_in_any_store_are_signed_out(settings, engine, mallory):
    settings.SESSION_ENGINE = engine
    browser = browser_of(mallory)
    suspend_accounts(BannedEmail.objects.create(email=BANNED))
    lift_bans(BannedEmail.objects.all())
    assert is_active(mallory)
    assert browser.get(ACCOUNT_PAGE).status_code == 302


@pytest.mark.django_db
@pytest.mark.parametrize(
    "engine", ["django.contrib.sessions.backends.db", "django.contrib.sessions.backends.cache"]
)
def test_a_rolled_back_ban_changes_nothing(settings, engine, mallory):
    settings.SESSION_ENGINE = engine
    browser = browser_of(mallory)
    with pytest.raises(RuntimeError), transaction.atomic():
        suspend_accounts(BannedEmail.objects.create(email=BANNED))
        raise RuntimeError("something after the suspension fails")
    assert is_active(mallory)
    assert browser.get(ACCOUNT_PAGE).status_code == 200


@pytest.mark.django_db
def test_a_ban_matching_nobody_signs_nobody_out(ban_in_admin, ada):
    browser = browser_of(ada)
    ban_in_admin("nobody@example.com")
    assert browser.get(ACCOUNT_PAGE).status_code == 200


@pytest.mark.django_db
def test_a_restored_account_without_an_email_isnt_emailed():
    if get_user_model()._meta.label != "auth.User":
        pytest.skip("capy-project's user model needs an email")
    nameless = get_user_model().objects.create_user(username="nameless", email="")
    send_restored_notices([nameless], RequestFactory().get("/"))
    assert mail.outbox == []
