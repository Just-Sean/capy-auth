"""Two-step sign-in is required for staff and superusers (capy_auth/mfa/staff.py, #30):
without it they can only set it up, confirm it's them, or sign out; a passkey sign-in
counts; the admin's login page goes to capy-auth's sign-in page; and the checks
capy_auth.E010 and E011."""

import pytest
from allauth.mfa.totp.internal.auth import TOTP, generate_totp_secret
from django.contrib import admin
from django.contrib.auth import SESSION_KEY
from django.test import Client
from django.urls import reverse

from capy_auth.mfa import checks
from capy_auth.mfa.checks import check_admin_login, check_staff_middleware
from tests import totp
from tests.accounts import ACCOUNT_PAGE, LOGIN, LOGOUT, PASSWORD, log_in
from tests.helpers import check_page
from tests.test_mfa import (
    AUTHENTICATE,
    DEACTIVATE,
    REAUTHENTICATE,
    confirmed,
    recovery_codes,
    set_up_app,
)
from tests.test_passkeys import add, passkey_login

ADMIN = "/admin/"
SET_UP = reverse("mfa_index")
CONFIRM_WITH_CODE = reverse("mfa_reauthenticate")
CONFIRM_WITH_PASSKEY = reverse("mfa_reauthenticate_webauthn")
SET_UP_MESSAGE = "Staff accounts need two-step sign-in. Set it up to continue."
CONFIRM_MESSAGE = "Staff accounts need two-step sign-in. Confirm it’s you to continue."


def make_staff(user, staff=True, superuser=False):
    """Staff, or a superuser (who needs staff too to open the admin)."""
    user.is_staff = staff
    user.is_superuser = superuser
    user.save()
    return user


def with_app(user):
    secret = generate_totp_secret()
    TOTP.activate(user, secret)
    return secret


# --- Without two-step sign-in ------------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize(("staff", "superuser"), [(True, False), (False, True), (True, True)])
@pytest.mark.parametrize("page", [ACCOUNT_PAGE, ADMIN, reverse("usersessions_list")])
def test_staff_without_it_are_sent_to_set_it_up_from_every_page(ada, staff, superuser, page):
    make_staff(ada, staff, superuser)
    client = Client()
    log_in(client)
    response = client.get(page)
    assert response.status_code == 302 and response.url == SET_UP
    assert SET_UP_MESSAGE in check_page(client.get(response.url))


@pytest.mark.django_db
@pytest.mark.parametrize("page", [SET_UP, REAUTHENTICATE, reverse("mfa_activate_totp")])
def test_meanwhile_the_two_step_pages_and_confirming_work(ada, page):
    make_staff(ada)
    client = Client()
    log_in(client)
    assert client.get(page).status_code in (200, 302)
    assert client.get(page).get("Location") != SET_UP


@pytest.mark.django_db
def test_meanwhile_signing_out_works(ada):
    make_staff(ada)
    client = Client()
    log_in(client)
    client.post(LOGOUT)
    assert SESSION_KEY not in client.session


@pytest.mark.django_db
def test_people_who_arent_staff_arent_asked(ada):
    client = Client()
    log_in(client)
    assert client.get(ACCOUNT_PAGE).status_code == 200


@pytest.mark.django_db
def test_someone_made_staff_while_signed_in_is_asked_at_the_next_page(ada):
    client = Client()
    log_in(client)
    make_staff(ada)
    assert client.get(ACCOUNT_PAGE).url == SET_UP


@pytest.mark.django_db
def test_setting_it_up_and_confirming_opens_the_admin(ada):
    make_staff(ada, superuser=True)
    client = Client()
    log_in(client)
    client.post(REAUTHENTICATE, {"password": PASSWORD})  # setting it up asks
    set_up_app(client)
    response = client.get(ADMIN)
    assert response.url == f"{CONFIRM_WITH_CODE}?next=%2Fadmin%2F"
    assert CONFIRM_MESSAGE in check_page(client.get(response.url))
    code = recovery_codes(client)[0]  # the app's code was just used to set it up
    response = client.post(response.url, {"code": code})
    assert response.url == ADMIN
    assert client.get(ADMIN).status_code == 200


@pytest.mark.django_db
def test_turning_it_off_sends_staff_back_to_set_it_up(ada):
    make_staff(ada)
    secret = with_app(ada)
    client = Client()
    log_in(client)
    client.post(AUTHENTICATE, {"code": totp.code(secret)})
    client.post(REAUTHENTICATE, {"password": PASSWORD})  # turning it off asks
    client.post(DEACTIVATE)
    assert client.get(ADMIN).url == SET_UP


# --- With two-step sign-in ----------------------------------------------------------------


@pytest.mark.django_db
def test_staff_who_used_the_second_step_go_straight_in(ada):
    make_staff(ada)
    secret = with_app(ada)
    client = Client()
    assert log_in(client).url == AUTHENTICATE
    client.post(AUTHENTICATE, {"code": totp.code(secret)})
    assert client.get(ADMIN).status_code == 200


@pytest.mark.django_db
def test_a_session_without_the_second_step_must_confirm_with_it(ada):
    """A session from before two-step sign-in was set up, or from before promotion."""
    make_staff(ada)
    secret = with_app(ada)
    client = Client()
    client.force_login(ada)
    response = client.get(ACCOUNT_PAGE)
    assert response.url == f"{CONFIRM_WITH_CODE}?next=%2Faccounts%2Fprofile%2F"
    client.post(REAUTHENTICATE, {"password": PASSWORD})  # the password alone isn't enough
    assert client.get(ACCOUNT_PAGE).url.startswith(CONFIRM_WITH_CODE)
    client.post(CONFIRM_WITH_CODE, {"code": totp.code(secret)})
    assert client.get(ACCOUNT_PAGE).status_code == 200


@pytest.mark.django_db
def test_a_passkey_sign_in_counts(ada):
    phone = add(confirmed(Client()))
    make_staff(ada, superuser=True)
    client = Client()
    passkey_login(client, phone)
    assert client.get(ADMIN).status_code == 200


@pytest.mark.django_db
def test_staff_with_only_a_passkey_confirm_with_it(ada):
    add(confirmed(Client()))
    make_staff(ada)
    client = Client()
    client.force_login(ada)
    assert client.get(ADMIN).url == f"{CONFIRM_WITH_PASSKEY}?next=%2Fadmin%2F"


# --- The admin's login page -----------------------------------------------------------------


@pytest.mark.django_db
def test_the_admin_sends_visitors_to_capy_auths_sign_in_page(client):
    response = client.get(ADMIN, follow=True)
    assert response.redirect_chain[-1][0] == f"{LOGIN}?next=%2Fadmin%2F"


@pytest.mark.django_db
def test_the_admin_refuses_signed_in_people_who_arent_staff(ada):
    client = Client()
    log_in(client)
    assert client.get(reverse("admin:login")).status_code == 403


# --- The checks ---------------------------------------------------------------------------


def test_without_the_middleware_the_site_doesnt_start(settings):
    assert check_staff_middleware(None) == []
    settings.MIDDLEWARE = [m for m in settings.MIDDLEWARE if m != checks.STAFF_MIDDLEWARE]
    [error] = check_staff_middleware(None)
    assert error.id == "capy_auth.E010" and checks.STAFF_MIDDLEWARE in error.hint


def test_with_the_admins_own_login_the_site_doesnt_start(monkeypatch):
    assert check_admin_login(None) == []
    monkeypatch.setattr(admin.site, "login", admin.site.login.__wrapped__)
    [error] = check_admin_login(None)
    assert error.id == "capy_auth.E011" and checks.ADMIN_LOGIN_LINE in error.hint


def test_without_the_admin_there_is_nothing_to_connect(monkeypatch):
    monkeypatch.setattr(admin.site, "login", admin.site.login.__wrapped__)
    monkeypatch.setattr(checks.apps, "is_installed", lambda name: False)
    assert check_admin_login(None) == []
