"""Two-step sign-in is required for staff and superusers (capy_auth/mfa/staff.py, #30):
setting it up (which counts) and "Continue"; confirming with it, where a password or
emailed code isn't offered and wouldn't count; a passkey sign-in counts; what the pages
say and how to sign out meanwhile; the admin's login page going to capy-auth's sign-in
page; and the checks capy_auth.E010 to E012. Ways to try to break it are in
test_staff_two_step_edges.py."""

import pytest
from django.contrib import admin
from django.test import Client
from django.urls import reverse

from capy_auth.mfa import checks
from capy_auth.mfa.checks import check_admin_login, check_staff_can_confirm, check_staff_middleware
from tests import totp
from tests.accounts import ACCOUNT_PAGE, LOGIN, PASSWORD, log_in
from tests.helpers import check_page
from tests.staff import CONFIRM_WITH_CODE, make_staff, with_app
from tests.test_mfa import AUTHENTICATE, DEACTIVATE, REAUTHENTICATE, confirmed, set_up_app
from tests.test_passkeys import ADD, add, passkey_login
from tests.webauthn import SoftPasskey, page_data

ADMIN = "/admin/"
SET_UP = reverse("mfa_index")
CONFIRM_WITH_PASSKEY = reverse("mfa_reauthenticate_webauthn")
RECOVERY_CODES = reverse("mfa_view_recovery_codes")
SET_UP_NOTE = "Your account is a staff account, so it needs two-step sign-in before"
CONFIRM_NOTE = "Your account is a staff account, so it needs two-step sign-in: confirm"
BACK_LINK = "Back to your account"
SIGN_OUT_BUTTON = '<button class="btn btn-outline" type="submit">Sign out</button>'


def staff_signed_in(user, **staff):
    make_staff(user, **staff)
    client = Client()
    log_in(client)
    return client


# --- Setting it up ------------------------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize(("staff", "superuser"), [(True, False), (False, True), (True, True)])
@pytest.mark.parametrize("page", [ACCOUNT_PAGE, ADMIN, reverse("usersessions_list")])
def test_staff_without_it_are_sent_to_set_it_up_from_every_page(ada, staff, superuser, page):
    response = staff_signed_in(ada, staff=staff, superuser=superuser).get(page)
    assert response.status_code == 302 and response.url == SET_UP


@pytest.mark.django_db
def test_the_set_up_page_says_why_and_offers_only_signing_out(ada):
    page = check_page(staff_signed_in(ada).get(SET_UP))
    assert SET_UP_NOTE in page and SIGN_OUT_BUTTON in page
    assert BACK_LINK not in page  # it would only lead back here


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("page", "status", "goes_to"),
    [
        (SET_UP, 200, None),
        (REAUTHENTICATE, 200, None),
        (reverse("account_request_reauthentication_code"), 200, None),
        (reverse("mfa_activate_totp"), 302, REAUTHENTICATE),  # setting it up asks first
        (ADD, 302, REAUTHENTICATE),
    ],
)
def test_meanwhile_the_set_up_pages_and_confirming_work(ada, page, status, goes_to):
    response = staff_signed_in(ada).get(page)
    assert response.status_code == status
    if goes_to:
        assert response.url.startswith(goes_to)


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


@pytest.mark.django_db(transaction=True)  # allauth tells of it once the save commits
def test_setting_up_the_app_counts_and_continue_goes_where_they_were_going(ada):
    client = staff_signed_in(ada, superuser=True)
    assert client.get(ADMIN).url == SET_UP
    client.post(REAUTHENTICATE, {"password": PASSWORD})  # setting it up asks
    set_up_app(client)
    page = check_page(client.get(RECOVERY_CODES))  # where allauth goes next: no extra code
    assert f'<a class="btn btn-primary" href="{ADMIN}">Continue</a>' in page
    assert client.get(ADMIN).status_code == 200
    assert "Continue" not in check_page(client.get(SET_UP))  # forgotten once used


@pytest.mark.django_db
def test_setting_up_a_passkey_counts(ada):
    client = staff_signed_in(ada)
    client.post(REAUTHENTICATE, {"password": PASSWORD})
    key = SoftPasskey()
    credential = key.register(page_data(check_page(client.get(ADD)))["creation_options"])
    client.post(ADD, {"name": "Phone", "credential": credential, "passwordless": "on"})
    assert client.get(ACCOUNT_PAGE).status_code == 200


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


# --- Confirming with it -------------------------------------------------------------------


@pytest.mark.django_db
def test_staff_who_used_the_second_step_go_straight_in(ada):
    make_staff(ada)
    secret = with_app(ada)
    client = Client()
    assert log_in(client).url == AUTHENTICATE
    client.post(AUTHENTICATE, {"code": totp.code(secret)})
    assert client.get(ADMIN).status_code == 200


@pytest.mark.django_db
def test_a_session_without_the_second_step_confirms_with_it_only(ada):
    """A session from before two-step sign-in was set up, or from before promotion."""
    make_staff(ada)
    secret = with_app(ada)
    client = Client()
    client.force_login(ada)
    response = client.get(ACCOUNT_PAGE)
    assert response.url == f"{CONFIRM_WITH_CODE}?next=%2Faccounts%2Fprofile%2F"
    page = check_page(client.get(response.url))
    assert CONFIRM_NOTE in page and SIGN_OUT_BUTTON in page
    assert "Use your password" not in page and "Send me a sign-in code" not in page
    assert "Before this change" not in page and BACK_LINK not in page
    assert client.get(REAUTHENTICATE).url.startswith(CONFIRM_WITH_CODE)  # not by password
    response = client.post(response.url, {"code": totp.code(secret)})
    assert response.url == ACCOUNT_PAGE
    assert client.get(ACCOUNT_PAGE).status_code == 200


@pytest.mark.django_db
def test_people_who_arent_staff_still_get_every_way_to_confirm(ada):
    with_app(ada)
    client = Client()
    client.force_login(ada)
    page = check_page(client.get(CONFIRM_WITH_CODE))
    assert "Use your password" in page and "Before this change" in page
    assert BACK_LINK in page and CONFIRM_NOTE not in page


@pytest.mark.django_db
def test_a_passkey_sign_in_counts(ada):
    phone = add(confirmed(Client()))
    make_staff(ada, superuser=True)
    client = Client()
    passkey_login(client, phone)
    assert client.get(ADMIN).status_code == 200


@pytest.mark.django_db
def test_staff_with_only_a_passkey_confirm_with_it(ada):
    phone = add(confirmed(Client()))
    make_staff(ada)
    client = Client()
    client.force_login(ada)
    response = client.get(ADMIN)
    assert response.url == f"{CONFIRM_WITH_PASSKEY}?next=%2Fadmin%2F"
    page = check_page(client.get(response.url))
    assert CONFIRM_NOTE in page
    client.post(response.url, {"credential": phone.sign(page_data(page)["request_options"])})
    assert client.get(ADMIN).status_code == 200


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


@pytest.mark.parametrize("where", ["missing", "first"])
def test_without_the_middleware_after_allauths_the_site_doesnt_start(settings, where):
    assert check_staff_middleware(None) == []
    rest = [m for m in settings.MIDDLEWARE if m != checks.STAFF_MIDDLEWARE]
    settings.MIDDLEWARE = rest if where == "missing" else [checks.STAFF_MIDDLEWARE, *rest]
    [error] = check_staff_middleware(None)
    assert error.id == "capy_auth.E010" and checks.ACCOUNT_MIDDLEWARE in error.hint


def test_without_two_step_as_a_way_to_confirm_the_site_doesnt_start(settings):
    assert check_staff_can_confirm(None) == []
    settings.ACCOUNT_REAUTHENTICATION_METHODS = ["password", "code"]
    assert [e.id for e in check_staff_can_confirm(None)] == ["capy_auth.E012"]


def test_the_check_looks_at_the_page_actually_served():
    """Not the admin.site.login attribute: set after urlpatterns, it changes nothing."""
    assert checks.served_admin_login() is admin.site.login
    assert check_admin_login(None) == []


def test_with_the_admins_own_login_page_the_site_doesnt_start(settings, monkeypatch):
    monkeypatch.setattr(checks, "served_admin_login", lambda: admin.site.login.__wrapped__)
    [error] = check_admin_login(None)
    assert error.id == "capy_auth.E011"
    assert checks.ADMIN_LOGIN_LINE in error.hint and settings.ROOT_URLCONF in error.hint


def test_without_the_admin_or_its_urls_there_is_nothing_to_connect(monkeypatch):
    monkeypatch.setattr(checks, "served_admin_login", lambda: None)
    assert check_admin_login(None) == []
    monkeypatch.setattr(checks, "served_admin_login", lambda: admin.site.login.__wrapped__)
    monkeypatch.setattr(checks.apps, "is_installed", lambda name: False)
    assert check_admin_login(None) == []


@pytest.mark.urls("tests.test_staff_two_step")
def test_a_site_without_the_admins_urls_has_none_served():
    assert checks.served_admin_login() is None


urlpatterns = []  # for the test above: a site with no admin URLs
