"""Signup, email verification by code, login, logout, password reset and password change,
with email and password only, as capy-auth sets allauth up."""

import re
import secrets
import string
from datetime import datetime, timedelta

import pytest
from allauth.account.forms import default_token_generator
from allauth.account.models import EmailAddress
from django.contrib.auth import get_user_model
from django.core import mail
from django.test import Client
from django.urls import reverse

from tests.accounts import (
    ACCOUNT_PAGE,
    CHANGE_PASSWORD,
    LOGIN,
    LOGOUT,
    NEW_PASSWORD,
    PASSWORD,
    RESET,
    SIGNUP,
    code_from,
    log_in,
    reset_link,
    sign_up,
    users_with_email,
)
from tests.helpers import check_page

# --- Signup and verification ---------------------------------------------------------


@pytest.mark.django_db
def test_signup_asks_only_for_email_and_password(client):
    page = check_page(client.get(SIGNUP))
    assert 'name="email"' in page
    assert 'name="password1"' in page
    assert 'name="username"' not in page


@pytest.mark.django_db
def test_signing_up_sends_a_code_and_the_code_finishes_signup(client):
    response = sign_up(client)
    assert response.status_code == 302
    user = users_with_email("eve@example.com").get()
    assert user.username  # allauth fills it in
    assert not EmailAddress.objects.get(user=user).verified
    assert len(mail.outbox) == 1
    code_page = client.get(response.url)
    check_page(code_page)
    assert client.get(ACCOUNT_PAGE).status_code == 302  # not logged in until verified

    response = client.post(response.url, {"code": code_from(mail.outbox[0])})
    assert response.status_code == 302
    assert EmailAddress.objects.get(user=user).verified
    page = check_page(client.get(ACCOUNT_PAGE))
    assert "eve@example.com" in page


@pytest.mark.django_db
def test_a_wrong_code_doesnt_verify(client):
    response = sign_up(client)
    page = check_page(client.post(response.url, {"code": "AAAA-AAAA"}))
    assert "<strong>Error:</strong>" in page
    assert not EmailAddress.objects.get(email="eve@example.com").verified


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("password", "reason"),
    [
        ("short words", "too short"),  # under 12 characters
        ("password1234", "too common"),
        ("839201748392", "entirely numeric"),
    ],
)
def test_weak_passwords_are_refused(client, password, reason):
    page = check_page(sign_up(client, password=password))
    assert reason in page
    assert not users_with_email("eve@example.com").exists()


@pytest.mark.django_db
def test_a_long_password_needs_no_digits_or_symbols(client):
    # NIST: a minimum length, no composition rules.
    letters_only = "".join(secrets.choice(string.ascii_lowercase) for _ in range(16))
    assert sign_up(client, password=letters_only).status_code == 302


@pytest.mark.django_db
def test_signing_up_with_a_taken_email_looks_the_same_and_creates_no_one(client, ada):
    new = sign_up(client, email="eve@example.com")
    taken = sign_up(Client(), email="ADA@Example.com")
    assert taken.status_code == new.status_code == 302
    assert taken.url == new.url
    assert users_with_email("ada@example.com").count() == 1
    # The owner is told someone tried; nobody else learns the account exists.
    assert any("ada@example.com" in message.to for message in mail.outbox)


# --- Login and logout ----------------------------------------------------------------


@pytest.mark.django_db
def test_logging_in_by_email_lands_on_the_account_page(client, ada):
    response = log_in(client, email="Ada@Example.com")
    assert response.status_code == 302
    assert response.url == ACCOUNT_PAGE
    check_page(client.get(ACCOUNT_PAGE))


@pytest.mark.django_db
def test_a_wrong_password_and_an_unknown_email_get_the_same_answer(client, ada):
    wrong = check_page(log_in(client, password=NEW_PASSWORD))
    unknown = check_page(log_in(client, email="nobody@example.com"))
    message = re.compile(r'<div role="alert" class="alert alert-error">([^<]+)</div>')
    assert message.search(wrong).group(1) == message.search(unknown).group(1)


@pytest.mark.django_db
def test_an_unverified_email_is_sent_a_code_instead_of_logging_in(client):
    user = get_user_model().objects.create_user(
        username="bob", email="bob@example.com", password=PASSWORD
    )
    EmailAddress.objects.create(user=user, email=user.email, primary=True, verified=False)
    response = log_in(client, email="bob@example.com")
    assert response.status_code == 302
    assert response.url != ACCOUNT_PAGE
    assert client.get(ACCOUNT_PAGE).status_code == 302
    assert len(mail.outbox) == 1


@pytest.mark.django_db
def test_a_next_link_to_another_site_is_ignored(client, ada):
    response = client.post(
        f"{LOGIN}?next=https://evil.example/",
        {"login": "ada@example.com", "password": PASSWORD, "next": "https://evil.example/"},
    )
    assert response.status_code == 302
    assert response.url == ACCOUNT_PAGE


@pytest.mark.django_db
def test_logout_asks_on_a_get_and_happens_on_a_post(client, ada):
    client.force_login(ada)
    check_page(client.get(LOGOUT))
    assert client.get(ACCOUNT_PAGE).status_code == 200  # the GET didn't log out
    client.post(LOGOUT)
    assert client.get(ACCOUNT_PAGE).status_code == 302


@pytest.mark.django_db
def test_the_account_page_needs_a_login_and_links_to_the_account_pages(client, ada):
    response = client.get(ACCOUNT_PAGE)
    assert response.status_code == 302
    assert response.url.startswith(LOGIN)
    client.force_login(ada)
    page = check_page(client.get(ACCOUNT_PAGE))
    assert "You're signed in as ada@example.com." in page
    # Managing email addresses comes in a later feature; until then it isn't linked.
    assert f'href="{reverse("account_email")}"' not in page
    assert f'href="{CHANGE_PASSWORD}"' in page
    assert f'action="{LOGOUT}"' in page


@pytest.mark.django_db
def test_a_login_stays_after_the_browser_closes(client, ada):
    log_in(client)
    assert client.session.get_expire_at_browser_close() is False


# --- Password reset ------------------------------------------------------------------


@pytest.mark.django_db
def test_a_reset_request_gets_the_same_answer_for_known_and_unknown_emails(client, ada):
    known = client.post(RESET, {"email": "ada@example.com"})
    unknown = client.post(RESET, {"email": "nobody@example.com"})
    assert known.status_code == unknown.status_code == 302
    assert known.url == unknown.url
    assert [message.to for message in mail.outbox if "reset" in message.subject.lower()] == [
        ["ada@example.com"]
    ]


@pytest.mark.django_db
def test_a_reset_link_works_once_and_tells_the_owner(client, ada):
    client.post(RESET, {"email": "ada@example.com"})
    link = reset_link(mail.outbox[0])
    form_page = client.get(link, follow=True)
    assert 'name="password1"' in check_page(form_page)
    form_url = form_page.redirect_chain[-1][0]
    response = client.post(form_url, {"password1": NEW_PASSWORD, "password2": NEW_PASSWORD})
    assert response.status_code == 302
    ada.refresh_from_db()
    assert ada.check_password(NEW_PASSWORD)
    assert any("password" in message.subject.lower() for message in mail.outbox[1:])

    again = Client().get(link, follow=True)
    assert 'name="password1"' not in again.content.decode()  # the link is used up


@pytest.mark.django_db
def test_a_reset_link_stops_working_after_an_hour(client, ada, monkeypatch):
    client.post(RESET, {"email": "ada@example.com"})
    link = reset_link(mail.outbox[0])
    assert 'name="password1"' in Client().get(link, follow=True).content.decode()  # works now
    later = datetime.now() + timedelta(hours=1, minutes=1)  # the token clock's own time
    monkeypatch.setattr(default_token_generator, "_now", lambda: later)
    page = client.get(link, follow=True).content.decode()
    assert 'name="password1"' not in page


# --- Password change -----------------------------------------------------------------


@pytest.mark.django_db
def test_changing_the_password_needs_the_current_one_and_tells_the_owner(client, ada):
    other_device = Client()
    other_device.force_login(ada)
    client.force_login(ada)
    wrong = client.post(
        CHANGE_PASSWORD,
        {"oldpassword": NEW_PASSWORD, "password1": NEW_PASSWORD, "password2": NEW_PASSWORD},
    )
    check_page(wrong)
    ada.refresh_from_db()
    assert ada.check_password(PASSWORD)

    response = client.post(
        CHANGE_PASSWORD,
        {"oldpassword": PASSWORD, "password1": NEW_PASSWORD, "password2": NEW_PASSWORD},
    )
    assert response.status_code == 302
    ada.refresh_from_db()
    assert ada.check_password(NEW_PASSWORD)
    assert any("password" in message.subject.lower() for message in mail.outbox)
    assert client.get(ACCOUNT_PAGE).status_code == 200  # this device stays logged in
    assert other_device.get(ACCOUNT_PAGE).status_code == 302  # others are logged out
