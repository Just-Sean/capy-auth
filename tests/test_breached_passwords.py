"""capy-auth's breached-password check (Have I Been Pwned): only a 5-character hash prefix
leaves the server, breached passwords are refused, and anything short of a good answer
refuses the password too (fails closed), at once for a minute after a failure."""

import hashlib
import importlib
import logging
import secrets
import socket
import ssl
from types import SimpleNamespace

import pytest
from django.apps import apps
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.exceptions import ValidationError

from capy_auth.config.checks import check_breached_password_validator, check_starting_values
from capy_auth.config.models import BreachedPasswordCheck
from capy_auth.config.selectors import get_auth_settings
from capy_auth.passwords import breached
from tests.hibp import PADDING, HibpStandIn, StandInResponse, answer, suffix_of

PASSWORD = secrets.token_urlsafe()
migration = importlib.import_module("capy_auth.migrations.0002_breached_password_check")


def set_level(level):
    record = get_auth_settings()
    record.breached_password_check = level
    record.save()


def service_answers(body, status=200):
    HibpStandIn.response = StandInResponse(status, body.encode() if isinstance(body, str) else body)


def refused_code(password=PASSWORD, user=None):
    with pytest.raises(ValidationError) as refused:
        breached.BreachedPasswordValidator().validate(password, user)
    return refused.value.error_list[0].code


def accepted(password=PASSWORD, user=None):
    breached.BreachedPasswordValidator().validate(password, user)
    return True


# --- What leaves the server ------------------------------------------------------------


@pytest.mark.django_db
def test_only_the_first_five_characters_of_the_hash_are_sent_over_https_with_padding():
    accepted()
    [made] = HibpStandIn.made
    digest = hashlib.sha1(PASSWORD.encode(), usedforsecurity=False).hexdigest().upper()
    assert (made.host, made.timeout) == ("api.pwnedpasswords.com", breached.TOTAL_SECONDS)
    assert (made.method, made.path) == ("GET", f"/range/{digest[:5]}")
    assert made.headers["Add-Padding"] == "true"
    assert PASSWORD not in repr(made.headers) and made.closed


# --- Answers ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_a_breached_password_is_refused():
    service_answers(answer(found=PASSWORD, count=42))
    assert refused_code() == "password_breached"


@pytest.mark.django_db
@pytest.mark.parametrize(
    "password",
    [
        "Grüße aus Köln, lange genug",
        "🦫 capybara 🦫 capybara",
        "密码密码密码密码密码密码",
        "x" * 100_000,
    ],
)
def test_any_password_is_hashed_as_utf8_and_found(password):
    service_answers(answer(found=password))
    assert refused_code(password) == "password_breached"


@pytest.mark.django_db
@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_line_endings_spaces_trailing_lines_and_lowercase_dont_matter(newline):
    lines = [*PADDING, f"  {suffix_of(PASSWORD).lower()} : 3  "]
    service_answers(newline.join(lines) + newline * 3)
    assert refused_code() in {"password_breached", "breached_check_unavailable"}
    service_answers(newline.join([*PADDING, f"{suffix_of(PASSWORD).lower()}:3"]) + newline)
    cache.clear()
    assert refused_code() == "password_breached"


@pytest.mark.django_db
@pytest.mark.parametrize(
    "bad_answer",
    [
        "",  # nothing at all
        "\r\n".join(PADDING[:10]),  # far too short to be a padded answer
        answer() + "\r\nnot a hash line",
        "\r\n".join([*PADDING, f"{suffix_of(PASSWORD)}:"]),  # count missing
        "\r\n".join([*PADDING, f"{suffix_of(PASSWORD)}:3.0"]),
        "\r\n".join([*PADDING, suffix_of(PASSWORD)]),  # no colon
    ],
)
def test_an_answer_that_isnt_understood_refuses_the_password(bad_answer):
    service_answers(bad_answer)
    assert refused_code() == "breached_check_unavailable"


@pytest.mark.django_db
def test_an_answer_far_too_big_refuses_the_password():
    service_answers(b"0" * (breached.MAX_ANSWER_BYTES + 1))
    assert refused_code() == "breached_check_unavailable"


@pytest.mark.django_db
def test_an_answer_too_slow_overall_refuses_the_password(monkeypatch):
    clock = iter(range(0, 1000, 2))  # each read takes 2 seconds
    monkeypatch.setattr(breached.time, "monotonic", lambda: next(clock))
    assert refused_code() == "breached_check_unavailable"


@pytest.mark.django_db
@pytest.mark.parametrize(
    "failure",
    [
        TimeoutError(),
        ssl.SSLCertVerificationError(),
        socket.gaierror(),
        ConnectionResetError(),
    ],
)
def test_every_network_failure_refuses_the_password(monkeypatch, failure):
    def fail(self, *args, **kwargs):
        raise failure

    monkeypatch.setattr(HibpStandIn, "request", fail)
    assert refused_code() == "breached_check_unavailable"


@pytest.mark.django_db
def test_an_error_status_refuses_the_password():
    service_answers(b"", status=503)
    assert refused_code() == "breached_check_unavailable"


@pytest.mark.django_db
def test_a_password_that_cant_be_encoded_is_still_checked():
    text = "abc\ud800 long enough to pass"  # a lone surrogate, possible from code
    assert accepted(text)


# --- When the service fails ------------------------------------------------------------


@pytest.mark.django_db
def test_after_a_failure_new_passwords_are_refused_at_once_for_a_minute(caplog):
    service_answers(b"", status=503)
    with caplog.at_level(logging.ERROR, logger="capy_auth"):
        assert refused_code(user=get_user_model()(email="eve@example.com")) == (
            "breached_check_unavailable"
        )
        assert refused_code() == "breached_check_unavailable"
    assert len(HibpStandIn.made) == 1  # the second wasn't sent to the service
    assert caplog.text.count("couldn't be reached or answered badly (HTTP 503)") == 1
    assert PASSWORD not in caplog.text and "eve@example.com" not in caplog.text
    cache.delete(breached.DOWN_KEY)  # the minute is over
    HibpStandIn.response = None
    assert accepted()


@pytest.mark.django_db
def test_with_the_cache_down_the_service_is_simply_asked_each_time(monkeypatch):
    def cache_down(*args, **kwargs):
        raise ConnectionError("cache unavailable")

    monkeypatch.setattr(breached.cache, "get", cache_down)
    monkeypatch.setattr(breached.cache, "set", cache_down)
    service_answers(b"", status=503)
    assert refused_code() == "breached_check_unavailable"
    HibpStandIn.response = None
    assert accepted()


def test_the_password_stays_out_of_error_reports():
    for function in (breached.times_breached, breached.ask_service):
        assert "password" in function.sensitive_variables
    assert {"digest", "suffix"} <= set(breached.times_breached.sensitive_variables)


# --- Who is checked --------------------------------------------------------------------


@pytest.mark.django_db
def test_switched_off_the_service_is_never_asked():
    set_level(BreachedPasswordCheck.OFF)
    service_answers(b"", status=503)
    assert accepted()
    assert HibpStandIn.made == []


@pytest.mark.django_db
@pytest.mark.parametrize(("staff", "superuser"), [(True, False), (False, True)])
def test_staff_and_superusers_level_checks_them(staff, superuser):
    set_level(BreachedPasswordCheck.STAFF)
    service_answers(answer(found=PASSWORD))
    assert refused_code(user=get_user_model()(is_staff=staff, is_superuser=superuser)) == (
        "password_breached"
    )


@pytest.mark.django_db
@pytest.mark.parametrize("user", [None, "plain", "no flags"])
def test_staff_and_superusers_level_skips_everyone_else(user):
    set_level(BreachedPasswordCheck.STAFF)
    person = {None: None, "plain": get_user_model()(), "no flags": object()}[user]
    assert accepted(user=person)
    assert HibpStandIn.made == []


@pytest.mark.django_db
def test_the_help_text_shows_only_when_everyone_is_checked():
    validator = breached.BreachedPasswordValidator()
    assert "data breach" in validator.get_help_text()
    for level in (BreachedPasswordCheck.STAFF, BreachedPasswordCheck.OFF):
        set_level(level)
        assert validator.get_help_text() == ""


# --- The setting and the project's setup ------------------------------------------------


@pytest.mark.django_db
def test_the_check_starts_on_for_everyone(settings):
    del settings.CAPY_AUTH_BREACHED_PASSWORD_CHECK
    assert get_auth_settings().breached_password_check == BreachedPasswordCheck.EVERYONE


@pytest.mark.django_db
def test_upgrading_copies_the_projects_setting_into_the_existing_record(settings):
    get_auth_settings()  # a site that already had the record
    settings.CAPY_AUTH_BREACHED_PASSWORD_CHECK = BreachedPasswordCheck.STAFF
    editor = SimpleNamespace(connection=SimpleNamespace(alias="default"))
    migration.copy_project_setting(apps, editor)
    assert get_auth_settings().breached_password_check == BreachedPasswordCheck.STAFF


@pytest.mark.parametrize("value", ["all", "Everyone", "", None, True])
def test_a_starting_value_that_isnt_a_level_gets_an_error(settings, value):
    settings.CAPY_AUTH_BREACHED_PASSWORD_CHECK = value
    [error] = check_starting_values(None)
    assert error.id == "capy_auth.E003" and "env.str" in error.hint


def test_a_project_without_the_validator_gets_a_warning(settings):
    assert check_breached_password_validator(None) == []
    settings.AUTH_PASSWORD_VALIDATORS = settings.AUTH_PASSWORD_VALIDATORS[:-1]
    assert [warning.id for warning in check_breached_password_validator(None)] == ["capy_auth.W003"]
