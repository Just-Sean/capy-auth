"""django-axes counts failed logins by the email typed; when the cache is down, sign-in
pages are a "temporarily unavailable" page (503), never open; and a production site
without email is stopped at startup (capy_auth.E004)."""

import logging

import pytest
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.cache.backends.locmem import LocMemCache
from django.test import Client, RequestFactory
from django.urls import resolve, reverse

from capy_auth.limits import middleware
from capy_auth.limits.axes import login_name
from capy_auth.limits.checks import check_email_can_be_sent
from tests.accounts import ACCOUNT_PAGE, LOGIN, PASSWORD, log_in
from tests.helpers import check_page

WRONG = PASSWORD + "-wrong"
FAILURE_LIMIT = 5  # AXES_FAILURE_LIMIT, as capy-project sets it


@pytest.fixture
def bob(ada):
    user = get_user_model().objects.create_user(
        username="bob", email="bob@example.com", password=PASSWORD
    )
    user.emailaddress_set.create(email=user.email, primary=True, verified=True)
    return user


def fail(client, email, times):
    for _ in range(times):
        log_in(client, email=email, password=WRONG)


# --- django-axes counts by the email -----------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("credentials", "post", "name"),
    [
        ({"email": " Ada@Example.com ", "password": "x"}, {}, "ada@example.com"),
        ({"username": "ada", "password": "x"}, {}, "ada@example.com"),  # the account's
        ({"username": "Nobody"}, {}, "nobody"),  # no such account
        (None, {"login": "ADA@example.com"}, "ada@example.com"),
        (None, {}, None),
    ],
)
def test_the_name_axes_counts_under(ada, credentials, post, name):
    assert login_name(RequestFactory().post("/", post), credentials) == name


def forget_allauths_counts():
    """allauth has its own, stricter limit (5 failures per email in 5 minutes, kept in
    the cache); clearing it shows what django-axes does on its own."""
    cache.clear()


@pytest.mark.django_db
def test_five_failures_lock_out_that_account_but_not_others_at_the_same_address(bob):
    client = Client()
    fail(client, "ada@example.com", FAILURE_LIMIT)
    assert log_in(client).status_code == 200  # refused, even with the right password
    forget_allauths_counts()
    assert log_in(client).status_code == 429  # django-axes' lockout, on its own
    assert log_in(Client(), email="bob@example.com").url == ACCOUNT_PAGE


@pytest.mark.django_db
def test_differently_typed_emails_count_together(ada):
    client = Client()
    for typed in ["ada@example.com", "ADA@example.com", " Ada@Example.com"]:
        fail(client, typed, 2)
    forget_allauths_counts()
    assert log_in(client).status_code == 429


@pytest.mark.django_db
def test_a_successful_login_clears_axes_count(ada):
    client = Client()
    fail(client, "ada@example.com", FAILURE_LIMIT - 1)
    assert log_in(client).url == ACCOUNT_PAGE
    forget_allauths_counts()
    fail(Client(), "ada@example.com", FAILURE_LIMIT - 1)
    assert log_in(Client()).url == ACCOUNT_PAGE


@pytest.mark.django_db
def test_the_admins_own_login_page_is_counted_by_username():
    get_user_model().objects.create_superuser(
        username="root", email="root@example.com", password=PASSWORD
    )
    admin_login = reverse("admin:login")
    client = Client()
    for _ in range(FAILURE_LIMIT):
        client.post(admin_login, {"username": "root", "password": WRONG})
    assert client.post(admin_login, {"username": "root", "password": PASSWORD}).status_code == 429


# --- The cache being down ----------------------------------------------------------------


@pytest.fixture
def cache_down(monkeypatch):
    def down(*args, **kwargs):
        raise ConnectionError("cache unavailable")  # as the cache raises when it's down

    for method in ("get", "set", "add", "incr", "delete", "get_many", "set_many"):
        monkeypatch.setattr(LocMemCache, method, down)


@pytest.mark.django_db
def test_with_the_cache_down_sign_in_is_a_503_page_and_nobody_gets_in(ada, cache_down, caplog):
    with caplog.at_level(logging.ERROR, logger="capy_auth"):
        response = log_in(Client())
    page = check_page(response, status=503)
    assert "temporarily unavailable" in page
    assert response["Retry-After"] == str(middleware.RETRY_AFTER_SECONDS)
    assert "sign-in pages are closed until it's back (ConnectionError)" in caplog.text


def test_only_account_pages_are_covered():
    login = RequestFactory().get(LOGIN)
    login.resolver_match = resolve(LOGIN)
    other = RequestFactory().get("/layout-check/")
    other.resolver_match = resolve("/layout-check/")
    assert middleware.is_account_page(login)
    assert not middleware.is_account_page(other)
    assert not middleware.is_account_page(RequestFactory().get("/nowhere/"))


def test_other_errors_with_the_cache_up_are_left_to_django():
    request = RequestFactory().get(LOGIN)
    request.resolver_match = resolve(LOGIN)
    handler = middleware.CacheDownMiddleware(lambda request: None)
    assert handler.process_exception(request, RuntimeError("a bug")) is None


def test_with_the_cache_down_other_pages_are_left_to_django(cache_down):
    request = RequestFactory().get("/layout-check/")
    request.resolver_match = resolve("/layout-check/")
    handler = middleware.CacheDownMiddleware(lambda request: None)
    assert handler.process_exception(request, ConnectionError()) is None


# --- Email must be set up in production --------------------------------------------------


@pytest.mark.parametrize(
    "backend",
    [
        "django.core.mail.backends.dummy.EmailBackend",
        "config.email_not_set_up.EmailNotSetUpBackend",
    ],
)
def test_a_production_site_without_email_is_stopped(settings, backend):
    settings.MAILERS = {"default": {"BACKEND": backend}}
    assert [error.id for error in check_email_can_be_sent(None)] == ["capy_auth.E004"]


def test_development_and_real_mailers_pass(settings):
    assert check_email_can_be_sent(None) == []  # the stand-in project's in-memory mailer
    settings.MAILERS = {"default": {"BACKEND": "django.core.mail.backends.smtp.EmailBackend"}}
    assert check_email_can_be_sent(None) == []
    settings.MAILERS = {"default": {"BACKEND": "django.core.mail.backends.dummy.EmailBackend"}}
    settings.DEBUG = True
    assert check_email_can_be_sent(None) == []


def test_a_project_without_mailers_isnt_checked(settings):
    del settings.MAILERS  # still on the deprecated EMAIL_BACKEND setting
    assert check_email_can_be_sent(None) == []
