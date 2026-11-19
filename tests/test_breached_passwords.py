"""capy-auth's breached-password check (Have I Been Pwned): only a 5-character hash prefix
leaves the server, breached passwords are refused, and when the service can't be reached
the password is refused too (fails closed). Admins choose nobody / staff / everyone."""

import hashlib
import importlib
import logging
import secrets

import pytest
from django.apps import apps
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

from capy_auth.config.checks import check_starting_values
from capy_auth.config.models import BreachedPasswordCheck
from capy_auth.config.selectors import get_auth_settings
from capy_auth.passwords import breached
from tests.accounts import sign_up
from tests.helpers import check_page

PASSWORD = secrets.token_urlsafe()
migration = importlib.import_module("capy_auth.migrations.0002_breached_password_check")


def answer_for(password, count):
    """HIBP's padded answer when the password appears `count` times (0: not at all)."""
    suffix = hashlib.sha1(password.encode(), usedforsecurity=False).hexdigest().upper()[5:]
    return f"0018A45C4D1DEF81644B54AB7F969B88D65:0\r\n{suffix}:{count}\r\nFFFF0000:0"


@pytest.fixture
def hibp(monkeypatch):
    """A fake Have I Been Pwned that remembers what it was asked and answers as told."""

    class Fake:
        asked = []
        answer = ""
        down = False

        def fetch(self, prefix):
            self.asked.append(prefix)
            if self.down:
                raise breached.ServiceUnavailable("TimeoutError")
            return self.answer

    fake = Fake()
    fake.asked = []
    monkeypatch.setattr(breached, "fetch_range", fake.fetch)
    return fake


def set_level(level):
    record = get_auth_settings()
    record.breached_password_check = level
    record.save()


def check(password, user=None):
    breached.BreachedPasswordValidator().validate(password, user)


# --- What it checks ------------------------------------------------------------------


@pytest.mark.django_db
def test_a_breached_password_is_refused(hibp):
    hibp.answer = answer_for(PASSWORD, 42)
    with pytest.raises(ValidationError) as refused:
        check(PASSWORD)
    assert refused.value.error_list[0].code == "password_breached"


@pytest.mark.django_db
def test_a_password_found_only_in_padding_is_accepted(hibp):
    hibp.answer = answer_for(PASSWORD, 0)  # padding lines have a count of 0
    check(PASSWORD)


@pytest.mark.django_db
def test_only_the_first_five_characters_of_the_hash_leave_the_server(hibp):
    hibp.answer = answer_for("other", 1)
    check(PASSWORD)
    digest = hashlib.sha1(PASSWORD.encode(), usedforsecurity=False).hexdigest().upper()
    assert hibp.asked == [digest[:5]]


@pytest.mark.django_db
def test_when_the_service_is_down_the_password_is_refused_and_logged(hibp, caplog):
    hibp.down = True
    with caplog.at_level(logging.ERROR, logger="capy_auth"), pytest.raises(ValidationError) as e:
        check(PASSWORD, get_user_model()(email="eve@example.com"))
    assert e.value.error_list[0].code == "breached_check_unavailable"
    assert "try again in a few minutes" in str(e.value)
    assert "couldn't be reached (TimeoutError)" in caplog.text
    assert PASSWORD not in caplog.text and "eve@example.com" not in caplog.text


# --- Who is checked ------------------------------------------------------------------


@pytest.mark.django_db
def test_switched_off_the_service_is_never_asked(hibp):
    set_level(BreachedPasswordCheck.OFF)
    hibp.down = True
    check(PASSWORD)
    assert hibp.asked == []


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("staff", "superuser", "asked"),
    [(False, False, False), (True, False, True), (False, True, True)],
)
def test_staff_only_checks_staff_and_superusers(hibp, staff, superuser, asked):
    set_level(BreachedPasswordCheck.STAFF)
    hibp.answer = answer_for("other", 1)
    check(PASSWORD, get_user_model()(is_staff=staff, is_superuser=superuser))
    check(PASSWORD, None)  # a signup has no staff account yet
    assert bool(hibp.asked) is asked


# --- On the pages --------------------------------------------------------------------


@pytest.mark.django_db
def test_signing_up_with_a_breached_password_is_refused(client, hibp):
    hibp.answer = answer_for(PASSWORD, 3)
    page = check_page(sign_up(client, password=PASSWORD))
    assert "appeared in a data breach" in page
    assert not get_user_model().objects.filter(email="eve@example.com").exists()


@pytest.mark.django_db
def test_signing_up_while_the_service_is_down_is_refused_with_the_reason(client, hibp):
    hibp.down = True
    page = check_page(sign_up(client, password=PASSWORD))
    assert "can&#x27;t check your password against known data breaches right now" in page
    assert not get_user_model().objects.filter(email="eve@example.com").exists()


@pytest.mark.django_db
def test_the_signup_page_says_breached_passwords_are_refused(client):
    assert "appeared in a data breach" in check_page(client.get("/accounts/signup/"))


# --- Asking the real service (with its connection faked) ------------------------------


class FakeConnection:
    made = []

    def __init__(self, host, timeout):
        self.host, self.timeout, self.closed = host, timeout, False
        FakeConnection.made.append(self)

    def request(self, method, path, headers):
        self.method, self.path, self.headers = method, path, headers

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


class FakeResponse:
    def __init__(self, status, body=b""):
        self.status, self.body = status, body

    def read(self, limit):
        self.limit = limit
        return self.body


@pytest.fixture
def connection(monkeypatch):
    monkeypatch.undo()  # the real fetch_range, not conftest's stand-in
    FakeConnection.made = []
    FakeConnection.response = FakeResponse(200, b"ABC:1")
    monkeypatch.setattr(breached, "HTTPSConnection", FakeConnection)
    return FakeConnection


def test_the_service_is_asked_over_https_with_padding_and_a_timeout(connection):
    assert breached.fetch_range("ABCDE") == "ABC:1"
    [made] = connection.made
    assert (made.host, made.timeout) == ("api.pwnedpasswords.com", 3)
    assert (made.method, made.path) == ("GET", "/range/ABCDE")
    assert made.headers["Add-Padding"] == "true"
    assert made.response.limit == breached.MAX_ANSWER_BYTES
    assert made.closed


@pytest.mark.parametrize(
    ("response", "reason"),
    [(FakeResponse(503), "HTTP 503"), (FakeResponse(200, b"\xff"), "UnicodeDecodeError")],
)
def test_a_bad_answer_counts_as_the_service_being_down(connection, response, reason):
    connection.response = response
    with pytest.raises(breached.ServiceUnavailable, match=reason):
        breached.fetch_range("ABCDE")


def test_a_network_error_counts_as_the_service_being_down(connection, monkeypatch):
    def no_network(self):
        raise ConnectionRefusedError

    monkeypatch.setattr(FakeConnection, "getresponse", no_network)
    with pytest.raises(breached.ServiceUnavailable, match="ConnectionRefusedError"):
        breached.fetch_range("ABCDE")
    assert connection.made[0].closed


# --- The setting ---------------------------------------------------------------------


@pytest.mark.django_db
def test_the_check_starts_on_for_everyone(settings):
    del settings.CAPY_AUTH_BREACHED_PASSWORD_CHECK
    assert get_auth_settings().breached_password_check == BreachedPasswordCheck.EVERYONE


@pytest.mark.django_db
def test_upgrading_copies_the_projects_setting_into_the_existing_record(settings):
    get_auth_settings()  # a site that already had the record
    settings.CAPY_AUTH_BREACHED_PASSWORD_CHECK = BreachedPasswordCheck.STAFF
    migration.copy_project_setting(apps, None)
    assert get_auth_settings().breached_password_check == BreachedPasswordCheck.STAFF


@pytest.mark.parametrize("value", ["all", "Everyone", "", None, True])
def test_a_starting_value_that_isnt_a_level_gets_an_error(settings, value):
    settings.CAPY_AUTH_BREACHED_PASSWORD_CHECK = value
    assert [error.id for error in check_starting_values(None)] == ["capy_auth.E002"]
