"""Trying to break passkeys (from the QA review of #28): who can and can't sign in with
one, limits, the cache going down, sessions, and managing them."""

import pytest
from allauth.account.models import EmailAddress
from allauth.mfa.models import Authenticator
from django.contrib.auth import SESSION_KEY, get_user_model
from django.core import mail
from django.core.cache import cache
from django.core.cache.backends.locmem import LocMemCache
from django.test import Client
from django.urls import reverse

from capy_auth.bans.models import BannedEmail
from capy_auth.bans.services import suspend_accounts
from tests import test_passkeys
from tests.accounts import LOGIN, PASSWORD, log_in
from tests.helpers import check_page
from tests.test_mfa import AUTHENTICATE, REAUTHENTICATE, confirmed
from tests.test_passkeys import (
    ADD,
    AJAX,
    LIST,
    PASSKEY_LOGIN,
    add,
    managing,
    passkey_login,
    signed_in,
)
from tests.webauthn import SoftPasskey, page_data

phone = test_passkeys.phone  # the fixture, shared
SESSIONS_PAGE = reverse("usersessions_list")


@pytest.fixture
def bob():
    user = get_user_model().objects.create_user(
        username="bob", email="bob@example.com", password=PASSWORD
    )
    EmailAddress.objects.create(user=user, email=user.email, primary=True, verified=True)
    return user


def edit_url(user):
    stored = Authenticator.objects.get(user=user, type="webauthn")
    return reverse("mfa_edit_webauthn", kwargs={"pk": stored.pk})


# --- Who can sign in with one ------------------------------------------------------------


@pytest.mark.django_db
def test_a_ban_removes_the_passkey_and_ends_its_sessions(ada, phone):
    client = Client()
    passkey_login(client, phone)
    suspend_accounts(BannedEmail.objects.create(email="ada@example.com"))
    assert not signed_in(client)
    assert not Authenticator.objects.filter(user=ada).exists()
    again = Client()
    passkey_login(again, phone)
    assert SESSION_KEY not in again.session


@pytest.mark.django_db
def test_an_unconfirmed_email_isnt_signed_in_by_a_passkey(ada, phone):
    EmailAddress.objects.filter(user=ada).update(verified=False)
    client = Client()
    passkey_login(client, phone)
    assert not signed_in(client)


@pytest.mark.django_db
def test_the_same_signed_answer_cant_sign_in_twice(phone):
    client = Client()
    options = client.get(PASSKEY_LOGIN, **AJAX).json()["request_options"]
    answer = phone.sign(options)
    client.post(PASSKEY_LOGIN, {"credential": answer})
    assert signed_in(client)
    client.logout()
    client.post(PASSKEY_LOGIN, {"credential": answer})
    assert not signed_in(client)


@pytest.mark.django_db
def test_another_users_passkey_cant_sign_in_as_me(ada, bob, phone):
    """Bob's own passkey, answering with Ada's account id, doesn't sign in as Ada."""
    bobs = add(confirmed_as(bob), name="Bob's phone")
    bobs.user_handle = phone.user_handle
    client = Client()
    passkey_login(client, bobs)
    assert not signed_in(client)


def confirmed_as(user):
    client = Client()
    client.post(LOGIN, {"login": user.email, "password": PASSWORD})
    client.post(REAUTHENTICATE, {"password": PASSWORD})
    return client


@pytest.mark.django_db
@pytest.mark.parametrize(("passwordless", "added"), [(True, False), (False, True)])
def test_a_key_without_a_pin_or_fingerprint_is_only_a_second_step(ada, passwordless, added):
    client = confirmed(Client())
    key = SoftPasskey()
    key.verifies_user = False
    data = {
        "name": "No PIN",
        "credential": key.register(page_data(check_page(client.get(ADD)))["creation_options"]),
    }
    if passwordless:
        data["passwordless"] = "on"
    client.post(ADD, data)
    assert Authenticator.objects.filter(user=ada, type="webauthn").exists() is added


@pytest.mark.django_db
def test_a_passkey_sign_in_without_a_pin_or_fingerprint_is_refused(phone):
    phone.verifies_user = False
    client = Client()
    passkey_login(client, phone)
    assert not signed_in(client)


@pytest.mark.django_db
def test_failed_passkey_sign_ins_are_rate_limited(phone):
    client = Client()
    stranger = SoftPasskey()
    stranger.user_handle = phone.user_handle
    statuses = []
    for _ in range(11):
        options = client.get(PASSKEY_LOGIN, **AJAX)
        if options.status_code != 200:
            statuses.append(options.status_code)
            continue
        credential = stranger.sign(options.json()["request_options"])
        statuses.append(client.post(PASSKEY_LOGIN, {"credential": credential}).status_code)
    assert 429 in statuses


@pytest.mark.django_db
def test_a_password_lockout_doesnt_block_the_passkey(ada, phone):
    """Documented choice (README, "Passkeys"): django-axes counts wrong passwords; a
    passkey can't be guessed, and allauth limits passkey attempts itself."""
    for _ in range(5):
        log_in(Client(), password=PASSWORD + "-wrong")
    cache.clear()  # allauth's own count; leave django-axes' lockout
    assert log_in(Client()).status_code == 429
    client = Client()
    passkey_login(client, phone)
    assert signed_in(client)


@pytest.mark.django_db
def test_passkey_sign_in_goes_to_next_but_never_off_site(phone):
    response = passkey_login(Client(), phone, next="/accounts/email/")
    assert response.url == "/accounts/email/"
    response = passkey_login(Client(), phone, next="https://evil.example/")
    assert "evil.example" not in response.url


# --- The cache going down ---------------------------------------------------------------


def break_cache(monkeypatch):
    def down(*args, **kwargs):
        raise ConnectionError("cache unavailable")

    for method in ("get", "set", "add", "incr", "delete", "get_many", "set_many"):
        monkeypatch.setattr(LocMemCache, method, down)


@pytest.mark.django_db
def test_with_the_cache_down_passkey_sign_in_is_the_503_page(phone, monkeypatch):
    client = Client(raise_request_exception=False)
    options = client.get(PASSKEY_LOGIN, **AJAX).json()["request_options"]
    break_cache(monkeypatch)
    response = client.post(PASSKEY_LOGIN, {"credential": phone.sign(options)})
    assert response.status_code == 503
    assert SESSION_KEY not in client.session


@pytest.mark.django_db
def test_with_the_cache_down_the_passkey_second_step_is_the_503_page(phone, monkeypatch):
    client = Client(raise_request_exception=False)
    log_in(client)
    options = page_data(check_page(client.get(AUTHENTICATE)))["request_options"]
    break_cache(monkeypatch)
    response = client.post(AUTHENTICATE, {"credential": phone.sign(options)})
    assert response.status_code == 503
    assert SESSION_KEY not in client.session


# --- Sessions ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_a_passkey_sign_in_is_listed_and_ended_by_sign_out_everywhere_else(ada, phone):
    by_passkey = Client(HTTP_USER_AGENT="Phone browser/1.0")
    passkey_login(by_passkey, phone)
    assert signed_in(by_passkey)
    laptop = managing(ada)
    assert "Phone browser/1.0" in check_page(laptop.get(SESSIONS_PAGE))
    laptop.post(SESSIONS_PAGE)
    assert not signed_in(by_passkey)


# --- Managing them ------------------------------------------------------------------------


@pytest.mark.django_db
def test_another_users_passkey_cant_be_renamed_or_removed(ada, bob, phone):
    stored = Authenticator.objects.get(user=ada, type="webauthn")
    client = managing(bob)
    edit = reverse("mfa_edit_webauthn", kwargs={"pk": stored.pk})
    remove = reverse("mfa_remove_webauthn", kwargs={"pk": stored.pk})
    assert client.get(edit).status_code == 404
    assert client.post(edit, {"name": "Mine now"}).status_code == 404
    assert client.post(remove).status_code == 404
    stored.refresh_from_db()
    assert stored.wrap().name == "My phone"


@pytest.mark.django_db
def test_a_name_with_html_is_shown_as_text(ada):
    add(confirmed(Client()), name='<img src=x onerror="alert(1)">')
    client = managing(ada)
    stored = Authenticator.objects.get(user=ada, type="webauthn")
    for path in (LIST, reverse("mfa_remove_webauthn", kwargs={"pk": stored.pk}), edit_url(ada)):
        page = check_page(client.get(path))
        assert "<img src=x" not in page
        assert "&lt;img src=x" in page


@pytest.mark.django_db
@pytest.mark.parametrize("name", ["   ", "x" * 101])
def test_a_blank_or_too_long_rename_is_refused(ada, phone, name):
    response = managing(ada).post(edit_url(ada), {"name": name})
    assert response.status_code == 200  # the form again, with the error
    stored = Authenticator.objects.get(user=ada, type="webauthn")
    assert stored.wrap().name == "My phone"


@pytest.mark.django_db
def test_a_too_long_name_isnt_added(ada):
    client = confirmed(Client())
    key = SoftPasskey()
    credential = key.register(page_data(check_page(client.get(ADD)))["creation_options"])
    client.post(ADD, {"name": "x" * 101, "credential": credential, "passwordless": "on"})
    assert not Authenticator.objects.filter(user=ada, type="webauthn").exists()


@pytest.mark.django_db
def test_removing_one_of_two_keeps_the_codes_and_the_other_signs_in(ada, phone):
    second = add(managing(ada), name="Laptop")
    stored = Authenticator.objects.get(user=ada, type="webauthn", data__name="My phone")
    managing(ada).post(reverse("mfa_remove_webauthn", kwargs={"pk": stored.pk}))
    assert Authenticator.objects.filter(user=ada, type="recovery_codes").exists()
    gone = Client()
    passkey_login(gone, phone)
    assert not signed_in(gone)
    other = Client()
    passkey_login(other, second)
    assert signed_in(other)


@pytest.mark.django_db
def test_adding_one_tells_the_owner_by_email(ada):
    mail.outbox.clear()
    add(confirmed(Client()))
    assert any("ada@example.com" in message.to for message in mail.outbox)
