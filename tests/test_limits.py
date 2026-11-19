"""django-axes counts failed logins under the account's main email; a lockout is a page
inside the layout; when the cache is down, account pages are a "temporarily unavailable"
page (503), never open; and a production site without email is stopped (capy_auth.E004)."""

import logging
from datetime import timedelta

import pytest
from allauth.account.models import EmailAddress
from axes.models import AccessAttempt
from django.contrib.auth import SESSION_KEY, get_user_model
from django.core.cache import cache
from django.core.cache.backends.locmem import LocMemCache
from django.core.exceptions import PermissionDenied
from django.http import Http404
from django.test import Client, RequestFactory
from django.urls import resolve, reverse
from django.utils import timezone

from capy_auth.limits import middleware
from capy_auth.limits.axes import login_name
from capy_auth.limits.checks import check_email_can_be_sent
from tests.accounts import ACCOUNT_PAGE, LOGIN, PASSWORD, RESET, SIGNUP, log_in, sign_up
from tests.helpers import check_page

WRONG = PASSWORD + "-wrong"
FAILURE_LIMIT = 5  # AXES_FAILURE_LIMIT, as capy-project sets it
ADMIN_LOGIN = reverse("admin:login")


@pytest.fixture
def bob(ada):
    user = get_user_model().objects.create_user(
        username="bob", email="bob@example.com", password=PASSWORD
    )
    EmailAddress.objects.create(user=user, email=user.email, primary=True, verified=True)
    return user


def fail(client, email, times):
    for _ in range(times):
        log_in(client, email=email, password=WRONG)


def forget_allauths_counts():
    """allauth has its own limit (5 failures per email in 5 minutes, kept in the
    cache); clearing it shows what django-axes does on its own."""
    cache.clear()


def resolved_get(path):
    request = RequestFactory().get(path)
    request.resolver_match = resolve(path)
    return request


# --- The name axes counts under ----------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("credentials", "post", "name"),
    [
        ({"email": " Ada@Example.com ", "password": "x"}, {}, "ada@example.com"),
        ({"email": "ada.alt@example.com"}, {}, "ada@example.com"),  # a second address
        ({"username": "ada", "password": "x"}, {}, "ada@example.com"),
        ({"username": "Nobody"}, {}, "nobody"),  # no such account
        ({"email": "Nobody@Example.com"}, {}, "nobody@example.com"),
        (None, {"login": "ADA@example.com"}, "ada@example.com"),
        (None, {"username": "ada"}, "ada@example.com"),  # the admin's form
        (None, {}, None),
    ],
)
def test_the_name_axes_counts_under(ada, credentials, post, name):
    EmailAddress.objects.create(user=ada, email="ada.alt@example.com", verified=True)
    assert login_name(RequestFactory().post("/", post), credentials) == name


# --- Lockouts ------------------------------------------------------------------------------


@pytest.mark.django_db
def test_five_failures_lock_out_that_account_but_not_others_at_the_same_address(bob):
    client = Client()
    fail(client, "ada@example.com", FAILURE_LIMIT)
    assert log_in(client).status_code == 200  # allauth refuses, even the right password
    assert SESSION_KEY not in client.session
    forget_allauths_counts()
    assert log_in(client).status_code == 429  # django-axes' lockout, on its own
    assert log_in(Client(), email="bob@example.com").url == ACCOUNT_PAGE


@pytest.mark.django_db
def test_four_failures_dont_lock(ada):
    client = Client()
    fail(client, "ada@example.com", FAILURE_LIMIT - 1)
    assert log_in(client).url == ACCOUNT_PAGE


@pytest.mark.django_db
def test_the_lockout_is_a_page_inside_the_layout_with_the_wait_and_a_reset_link(ada):
    client = Client()
    fail(client, "ada@example.com", FAILURE_LIMIT)
    forget_allauths_counts()
    page = check_page(log_in(client), status=429)
    assert "<title>Too many attempts" in page
    assert "Too many attempts</h1>" in page
    assert "Please wait 15 minutes" in page
    assert f'href="{RESET}"' in page


@pytest.mark.django_db
def test_differently_typed_emails_count_together(ada):
    client = Client()
    for typed in ["ada@example.com", "ADA@example.com", " Ada@Example.com"]:
        fail(client, typed, 2)
    forget_allauths_counts()
    assert log_in(client).status_code == 429


@pytest.mark.django_db
def test_an_accounts_second_address_shares_its_count(ada):
    EmailAddress.objects.create(user=ada, email="ada.alt@example.com", verified=True)
    client = Client()
    fail(client, "ada@example.com", FAILURE_LIMIT)
    forget_allauths_counts()
    assert log_in(client, email="ada.alt@example.com").status_code == 429


@pytest.mark.django_db
def test_a_successful_login_clears_axes_count(ada):
    client = Client()
    fail(client, "ada@example.com", FAILURE_LIMIT - 1)
    assert log_in(client).url == ACCOUNT_PAGE
    forget_allauths_counts()
    fail(Client(), "ada@example.com", FAILURE_LIMIT - 1)
    assert log_in(Client()).url == ACCOUNT_PAGE


@pytest.mark.django_db
def test_the_admins_own_login_page_is_counted_too():
    get_user_model().objects.create_superuser(
        username="root", email="root@example.com", password=PASSWORD
    )
    client = Client()
    for _ in range(FAILURE_LIMIT):
        client.post(ADMIN_LOGIN, {"username": "root", "password": WRONG})
    assert client.post(ADMIN_LOGIN, {"username": "root", "password": PASSWORD}).status_code == 429


@pytest.mark.django_db
def test_admin_and_allauth_failures_add_up_to_one_count():
    root = get_user_model().objects.create_superuser(
        username="root", email="root@example.com", password=PASSWORD
    )
    EmailAddress.objects.create(user=root, email=root.email, primary=True, verified=True)
    client = Client()
    for _ in range(3):
        client.post(ADMIN_LOGIN, {"username": "root", "password": WRONG})
    fail(client, "root@example.com", 2)
    forget_allauths_counts()
    assert client.post(ADMIN_LOGIN, {"username": "root", "password": PASSWORD}).status_code == 429


@pytest.mark.django_db
def test_behind_the_proxy_a_forged_forwarded_address_doesnt_escape(settings, ada):
    """The proxy appends the real address last; whatever a visitor puts before it is
    ignored, so changing it each time doesn't reset the count."""
    settings.BEHIND_PROXY = True
    for forged in range(FAILURE_LIMIT):
        attacker = Client(
            REMOTE_ADDR="10.0.0.2", HTTP_X_FORWARDED_FOR=f"198.51.100.{forged}, 203.0.113.66"
        )
        log_in(attacker, password=WRONG)
    forget_allauths_counts()
    attacker = Client(REMOTE_ADDR="10.0.0.2", HTTP_X_FORWARDED_FOR="9.9.9.9, 203.0.113.66")
    assert log_in(attacker).status_code == 429
    assert AccessAttempt.objects.get().ip_address == "203.0.113.66"


@pytest.mark.django_db
def test_signup_and_reset_dont_count_and_a_locked_out_person_can_reset(ada):
    client = Client()
    for _ in range(FAILURE_LIMIT):
        sign_up(client, email="ada@example.com")
        client.post(RESET, {"email": "ada@example.com"})
    assert not AccessAttempt.objects.exists()
    fail(client, "ada@example.com", FAILURE_LIMIT)
    forget_allauths_counts()
    assert client.post(RESET, {"email": "ada@example.com"}).status_code == 302


@pytest.mark.django_db
@pytest.mark.parametrize(("minutes_ago", "locked"), [(14, True), (16, False)])
def test_the_lockout_lasts_the_cool_off(ada, minutes_ago, locked):
    client = Client()
    fail(client, "ada@example.com", FAILURE_LIMIT)
    forget_allauths_counts()
    AccessAttempt.objects.update(attempt_time=timezone.now() - timedelta(minutes=minutes_ago))
    assert (log_in(client).status_code == 429) is locked


# --- The cache being down ----------------------------------------------------------------

ALL_CACHE_METHODS = ("get", "set", "add", "incr", "delete", "get_many", "set_many")
WRITE_METHODS = ("set", "add", "incr", "set_many")


def break_cache(monkeypatch, methods=ALL_CACHE_METHODS):
    def down(*args, **kwargs):
        raise ConnectionError("cache unavailable")  # as the cache raises when it's down

    for method in methods:
        monkeypatch.setattr(LocMemCache, method, down)


@pytest.mark.django_db
@pytest.mark.parametrize("path", [LOGIN, SIGNUP, RESET])
def test_with_the_cache_down_account_pages_are_a_503_page_and_nobody_gets_in(
    ada, monkeypatch, caplog, path
):
    break_cache(monkeypatch)
    client = Client()
    data = {"login": "ada@example.com", "email": "ada@example.com", "password": PASSWORD}
    with caplog.at_level(logging.ERROR, logger="capy_auth"):
        response = client.post(path, data)
    page = check_page(response, status=503)
    assert "temporarily unavailable" in page
    assert response["Retry-After"] == str(middleware.RETRY_AFTER_SECONDS)
    assert SESSION_KEY not in client.session
    assert "account pages are closed until it's back" in caplog.text
    assert "ConnectionError: cache unavailable" in caplog.text  # the traceback is kept


@pytest.mark.django_db
def test_a_cache_that_reads_but_cant_write_is_down_too(ada, monkeypatch):
    break_cache(monkeypatch, WRITE_METHODS)
    check_page(log_in(Client()), status=503)


@pytest.mark.django_db
def test_with_the_cache_down_reading_account_pages_still_works(monkeypatch):
    break_cache(monkeypatch)
    for path in (LOGIN, SIGNUP, RESET):
        assert Client().get(path).status_code == 200


def test_the_probe_tells_a_cache_that_cant_write_from_a_working_one(monkeypatch):
    assert not middleware.cache_is_down()
    break_cache(monkeypatch, WRITE_METHODS)
    assert middleware.cache_is_down()


def test_only_account_pages_are_covered():
    assert middleware.is_account_page(resolved_get(LOGIN))
    assert not middleware.is_account_page(resolved_get("/layout-check/"))
    assert not middleware.is_account_page(RequestFactory().get("/nowhere/"))


def test_other_errors_with_the_cache_up_are_left_to_django():
    handler = middleware.CacheDownMiddleware(lambda request: None)
    assert handler.process_exception(resolved_get(LOGIN), RuntimeError("a bug")) is None


def test_a_missing_page_or_a_refusal_is_left_to_django_even_with_the_cache_down(monkeypatch):
    break_cache(monkeypatch)
    handler = middleware.CacheDownMiddleware(lambda request: None)
    for error in (Http404(), PermissionDenied()):
        assert handler.process_exception(resolved_get(LOGIN), error) is None


def test_with_the_cache_down_other_pages_are_left_to_django(monkeypatch):
    break_cache(monkeypatch)
    handler = middleware.CacheDownMiddleware(lambda request: None)
    assert handler.process_exception(resolved_get("/layout-check/"), ConnectionError()) is None


def test_a_cache_clients_own_error_needs_no_second_call(monkeypatch):
    class RedisConnectionError(Exception):
        __module__ = "redis.exceptions"

    probes = []
    monkeypatch.setattr(middleware, "cache_is_down", lambda: probes.append(1) or True)
    assert middleware.raised_by_cache(RedisConnectionError())
    assert not middleware.raised_by_cache(RuntimeError())
    handler = middleware.CacheDownMiddleware(lambda request: None)
    response = handler.process_exception(resolved_get(LOGIN), RedisConnectionError())
    assert response.status_code == 503
    assert probes == []


# --- Email must be set up in production --------------------------------------------------


@pytest.mark.parametrize(
    "mailers",
    [
        {"default": {"BACKEND": "django.core.mail.backends.dummy.EmailBackend"}},
        {"default": {"BACKEND": "django.core.mail.backends.console.EmailBackend"}},
        {"default": {"BACKEND": "django.core.mail.backends.filebased.EmailBackend"}},
        {"default": {"BACKEND": "config.email_not_set_up.EmailNotSetUpBackend"}},
        {},
        {"transactional": {"BACKEND": "django.core.mail.backends.smtp.EmailBackend"}},
        None,
    ],
)
def test_a_production_site_without_working_email_is_stopped(settings, mailers):
    settings.MAILERS = mailers
    assert [error.id for error in check_email_can_be_sent(None)] == ["capy_auth.E004"]


@pytest.mark.parametrize(
    "mailers",
    [
        {"default": {"BACKEND": "django.core.mail.backends.locmem.EmailBackend"}},  # tests
        {"default": {"BACKEND": "django.core.mail.backends.smtp.EmailBackend"}},
        {"default": {"OPTIONS": {"host": "smtp.example.com"}}},  # SMTP is the default
    ],
)
def test_real_and_test_mailers_pass(settings, mailers):
    settings.MAILERS = mailers
    assert check_email_can_be_sent(None) == []


def test_development_isnt_checked(settings):
    settings.MAILERS = {"default": {"BACKEND": "django.core.mail.backends.dummy.EmailBackend"}}
    settings.DEBUG = True
    assert check_email_can_be_sent(None) == []


def test_a_project_without_mailers_isnt_checked(settings):
    del settings.MAILERS  # still on the deprecated EMAIL_BACKEND setting
    assert check_email_can_be_sent(None) == []
