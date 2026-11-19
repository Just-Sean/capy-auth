"""Asking for the password again before sensitive changes (allauth's reauthentication,
for 5 minutes after the password is typed), the "Signed-in devices" page with "Sign
out everywhere else", and the check capy_auth.E006."""

import pytest
from allauth.account.internal.flows.login import AUTHENTICATION_METHODS_SESSION_KEY
from django.apps import apps
from django.test import Client
from django.urls import reverse

from capy_auth.sessions.checks import (
    SESSIONS_APP,
    SESSIONS_MIDDLEWARE,
    check_user_sessions,
)
from tests.accounts import ACCOUNT_PAGE, LOGIN, PASSWORD, log_in
from tests.helpers import check_page

SESSIONS_PAGE = reverse("usersessions_list")
EMAIL_PAGE = reverse("account_email")
REAUTHENTICATE = reverse("account_reauthenticate")
FIVE_MINUTES = 300


def signed_in(client_class, user_agent):
    client = client_class(HTTP_USER_AGENT=user_agent)
    assert log_in(client).url == ACCOUNT_PAGE
    return client


def add_email(client):
    return client.post(EMAIL_PAGE, {"email": "ada.work@example.com", "action_add": ""})


def typed_password_seconds_ago(client, seconds):
    """Moves the time allauth recorded for the last password re-entry back."""
    session = client.session
    records = session[AUTHENTICATION_METHODS_SESSION_KEY]
    for record in records:
        record["at"] -= seconds
    session[AUTHENTICATION_METHODS_SESSION_KEY] = records
    session.save()


# --- Asking again -----------------------------------------------------------------------


@pytest.mark.django_db
def test_a_change_right_after_signing_in_asks_for_the_password_again(client, ada):
    log_in(client)
    response = add_email(client)
    assert response.url.startswith(REAUTHENTICATE)


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("seconds_ago", "asks"), [(FIVE_MINUTES - 30, False), (FIVE_MINUTES + 30, True)]
)
def test_the_password_is_asked_again_after_five_minutes(client, ada, seconds_ago, asks):
    log_in(client)
    client.post(REAUTHENTICATE, {"password": PASSWORD})
    typed_password_seconds_ago(client, seconds_ago)
    response = add_email(client)
    assert response.url.startswith(REAUTHENTICATE) is asks


@pytest.mark.django_db
def test_a_wrong_password_doesnt_count(client, ada):
    log_in(client)
    page = client.post(REAUTHENTICATE, {"password": PASSWORD + "-wrong"})
    assert page.status_code == 200
    assert add_email(client).url.startswith(REAUTHENTICATE)


@pytest.mark.django_db
def test_changing_the_password_always_asks_for_the_current_one(client, ada):
    log_in(client)
    page = client.post(
        reverse("account_change_password"),
        {"oldpassword": "", "password1": PASSWORD + "x", "password2": PASSWORD + "x"},
    )
    assert page.status_code == 200
    ada.refresh_from_db()
    assert ada.check_password(PASSWORD)


# --- Signed-in devices ----------------------------------------------------------------------


@pytest.mark.django_db
def test_the_account_page_links_to_signed_in_devices(client, ada):
    log_in(client)
    assert f'href="{SESSIONS_PAGE}"' in check_page(client.get(ACCOUNT_PAGE))


@pytest.mark.django_db
def test_the_page_lists_each_sign_in_and_marks_this_one(ada):
    phone = signed_in(Client, "Phone browser/1.0")
    laptop = signed_in(Client, "Laptop browser/2.0")
    page = check_page(laptop.get(SESSIONS_PAGE))
    assert "Phone browser/1.0" in page and "Laptop browser/2.0" in page
    assert page.count("This device") == 1
    assert "IP address: 127.0.0.1" in page
    assert "Sign out everywhere else" in page
    assert f'action="{SESSIONS_PAGE}"' in page
    assert f'href="{ACCOUNT_PAGE}"' in page
    assert phone.get(ACCOUNT_PAGE).status_code == 200


@pytest.mark.django_db
def test_sign_out_everywhere_else_ends_the_other_sessions_and_keeps_this_one(ada):
    phone = signed_in(Client, "Phone browser/1.0")
    tablet = signed_in(Client, "Tablet browser/1.0")
    laptop = signed_in(Client, "Laptop browser/2.0")
    page = check_page(laptop.post(SESSIONS_PAGE, follow=True))
    assert "Signed out of all other sessions." in page
    assert "Phone browser/1.0" not in page
    assert phone.get(ACCOUNT_PAGE).status_code == 302  # signed out
    assert tablet.get(ACCOUNT_PAGE).status_code == 302
    assert laptop.get(ACCOUNT_PAGE).status_code == 200  # still signed in


@pytest.mark.django_db
def test_with_one_session_the_button_signs_out(client, ada):
    log_in(client)
    page = check_page(client.get(SESSIONS_PAGE))
    assert f'action="{reverse("account_logout")}"' in page
    assert "Sign out everywhere else" not in page


@pytest.mark.django_db
def test_the_page_needs_a_sign_in(client):
    response = client.get(SESSIONS_PAGE)
    assert response.status_code == 302
    assert response.url.startswith(LOGIN)


@pytest.mark.django_db
def test_a_browser_that_sends_no_description_is_shown_as_unknown(ada):
    client = signed_in(Client, "")
    assert "Unknown browser" in check_page(client.get(SESSIONS_PAGE))


# --- The startup check ------------------------------------------------------------------------


def test_the_stand_in_project_has_user_sessions():
    assert check_user_sessions(None) == []


def test_without_the_middleware_the_site_is_stopped(settings):
    settings.MIDDLEWARE = [m for m in settings.MIDDLEWARE if m != SESSIONS_MIDDLEWARE]
    errors = check_user_sessions(None)
    assert [error.id for error in errors] == ["capy_auth.E006"]
    assert SESSIONS_MIDDLEWARE in errors[0].msg


def test_without_the_app_the_site_is_stopped(monkeypatch):
    monkeypatch.setattr(apps, "is_installed", lambda name: name != SESSIONS_APP)
    errors = check_user_sessions(None)
    assert [error.id for error in errors] == ["capy_auth.E006"]
    assert SESSIONS_APP in errors[0].msg
