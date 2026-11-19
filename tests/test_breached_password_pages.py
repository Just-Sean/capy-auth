"""The breached-password check on every page and command that sets a password: signup,
password change and reset, the admin and createsuperuser."""

import secrets
from io import StringIO

import pytest
from allauth.core.context import request_context
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core import mail
from django.core.management import call_command
from django.test import RequestFactory
from django.urls import reverse

from capy_auth.config.models import AuthSettings, BreachedPasswordCheck
from capy_auth.config.selectors import get_auth_settings
from tests.accounts import CHANGE_PASSWORD, PASSWORD, RESET, reset_link, sign_up
from tests.helpers import check_page
from tests.hibp import HibpStandIn, StandInResponse, answer
from tests.staff import two_step_client

NEW = secrets.token_urlsafe()
EMAIL_USERS = settings.TEST_USER_MODEL == "email"
SETTINGS_PAGE = reverse("admin:capy_auth_authsettings_change", args=[AuthSettings.SINGLETON_ID])
BREACHED = "appeared in a data breach"
UNAVAILABLE = "check this password against known data breaches right now"


def new_password_breached():
    HibpStandIn.response = StandInResponse(body=answer(found=NEW).encode())


def service_down():
    HibpStandIn.response = StandInResponse(503, b"")


def set_level(level):
    record = get_auth_settings()
    record.breached_password_check = level
    record.save()


# --- Signup ----------------------------------------------------------------------------


@pytest.mark.django_db
def test_signing_up_with_a_breached_password_is_refused(client):
    new_password_breached()
    page = check_page(sign_up(client, password=NEW))
    assert BREACHED in page and "change it there too" in page
    assert not get_user_model().objects.filter(email="eve@example.com").exists()


@pytest.mark.django_db
def test_signing_up_while_the_service_is_down_is_refused_with_the_reason(client):
    service_down()
    page = check_page(sign_up(client, password=NEW))
    assert UNAVAILABLE in page
    assert not get_user_model().objects.filter(email="eve@example.com").exists()


@pytest.mark.django_db
def test_the_help_text_is_shown_only_when_it_applies(client):
    assert BREACHED in check_page(client.get(reverse("account_signup")))
    set_level(BreachedPasswordCheck.OFF)
    page = check_page(client.get(reverse("account_signup")))
    assert BREACHED not in page and "<li></li>" not in page


# --- Password change and reset -----------------------------------------------------------


@pytest.mark.django_db
def test_a_staff_password_change_is_checked_at_the_staff_level(client, ada):
    set_level(BreachedPasswordCheck.STAFF)
    ada.is_staff = True
    ada.save()
    two_step_client(ada, client)
    new_password_breached()
    page = check_page(
        client.post(CHANGE_PASSWORD, {"oldpassword": PASSWORD, "password1": NEW, "password2": NEW})
    )
    assert BREACHED in page
    ada.refresh_from_db()
    assert ada.check_password(PASSWORD)


@pytest.mark.django_db
def test_a_reset_is_refused_while_the_service_is_down(client, ada):
    client.post(RESET, {"email": "ada@example.com"})
    form_page = client.get(reset_link(mail.outbox[0]), follow=True)
    service_down()
    response = client.post(form_page.redirect_chain[-1][0], {"password1": NEW, "password2": NEW})
    assert UNAVAILABLE in check_page(response)
    ada.refresh_from_db()
    assert ada.check_password(PASSWORD)


# --- The admin and createsuperuser -------------------------------------------------------


@pytest.fixture
def superuser_client():
    superuser = get_user_model().objects.create_superuser(
        username="root", email="root@example.com", password=PASSWORD
    )
    return two_step_client(superuser)


@pytest.mark.django_db
@pytest.mark.parametrize("level", ["staff", "off"])
def test_an_admin_sets_the_level_on_the_settings_page(superuser_client, level):
    get_auth_settings()
    superuser_client.post(
        SETTINGS_PAGE, {"_save": "Save", "signup_open": "on", "breached_password_check": level}
    )
    assert AuthSettings.objects.get().breached_password_check == level


@pytest.mark.django_db
@pytest.mark.skipif(EMAIL_USERS, reason="the stand-in project's admin lists Django's users only")
def test_the_admins_add_user_form_refuses_a_breached_password(superuser_client):
    new_password_breached()
    page = superuser_client.post(
        reverse("admin:auth_user_add"),
        {"username": "bob", "usable_password": "true", "password1": NEW, "password2": NEW},
    ).content.decode()
    assert BREACHED in page
    assert not get_user_model().objects.filter(username="bob").exists()


@pytest.mark.django_db
def test_createsuperuser_refuses_a_breached_password(monkeypatch):
    new_password_breached()
    answers = iter([NEW, NEW, "N"] * 3)  # password, again, "bypass the rules?": no
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(answers))
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))

    class Terminal(StringIO):
        def isatty(self):
            return True

    errors = StringIO()
    fields = {"email": "root@example.com", "username": "root"}  # both user models ask
    with pytest.raises(StopIteration):  # it keeps asking until the answers run out
        call_command("createsuperuser", interactive=True, stdin=Terminal(), stderr=errors, **fields)
    assert BREACHED in errors.getvalue()
    assert not get_user_model().objects.filter(email="root@example.com").exists()


# --- The settings record is read once per request ----------------------------------------


@pytest.mark.django_db
def test_within_a_request_the_record_is_read_once(django_assert_num_queries):
    get_auth_settings()
    with request_context(RequestFactory().get("/")):
        with django_assert_num_queries(1):
            get_auth_settings()
            get_auth_settings()


@pytest.mark.django_db
def test_each_request_reads_the_record_afresh():
    set_level(BreachedPasswordCheck.STAFF)
    with request_context(RequestFactory().get("/")):
        assert get_auth_settings().breached_password_check == BreachedPasswordCheck.STAFF
    set_level(BreachedPasswordCheck.OFF)
    with request_context(RequestFactory().get("/")):
        assert get_auth_settings().breached_password_check == BreachedPasswordCheck.OFF
