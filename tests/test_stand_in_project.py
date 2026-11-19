"""The stand-in project gives the module what a capy project gives it: allauth, the strict
Content Security Policy, layout.html with its messages region, and the user model being
tested (Django's default, or a capy-project user with TEST_USER_MODEL=email)."""

import re
import runpy
import secrets
from io import StringIO
from pathlib import Path

import pytest
from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.core.management import call_command
from django.db import IntegrityError, transaction
from django.test import RequestFactory

ADMIN_LOGIN = "/admin/login/"
LAYOUT_CHECK = "/layout-check/"
SETTINGS_FILE = Path(__file__).resolve().parent / "settings.py"
EMAIL_USERS = settings.TEST_USER_MODEL == "email"
email_users_only = pytest.mark.skipif(
    not EMAIL_USERS, reason="only the capy-project user model has these rules"
)
PASSWORD = secrets.token_urlsafe()  # made each run, so no password is written here

# capy-project's policy (config/settings/security.py), as the browser receives it, with
# each page's nonce value replaced by 'nonce'. Written out rather than read from the
# settings, so a change to the stand-in project's policy fails here.
CAPY_PROJECT_POLICY = {
    "default-src": ["'none'"],
    "script-src": ["'self'", "'nonce'"],
    "style-src": ["'self'", "'nonce'"],
    "img-src": ["'self'", "data:"],
    "font-src": ["'self'"],
    "connect-src": ["'self'"],
    "object-src": ["'none'"],
    "base-uri": ["'self'"],
    "form-action": ["'self'"],
    "frame-ancestors": ["'none'"],
}


def parse_policy(header):
    policy = {}
    for directive in header.split(";"):
        name, *sources = directive.split()
        policy[name] = [re.sub(r"^'nonce-[^']+'$", "'nonce'", source) for source in sources]
    return policy


def test_pages_get_exactly_capy_projects_policy(client):
    # The admin's login page uses the nonce, so the header carries it.
    response = client.get(ADMIN_LOGIN)
    assert response.status_code == 200
    assert parse_policy(response.headers["Content-Security-Policy"]) == CAPY_PROJECT_POLICY


def test_a_page_in_the_layout_gets_its_blocks_and_escaped_messages(client):
    response = client.get(LAYOUT_CHECK)
    assert response.status_code == 200
    assert "Content-Security-Policy" in response.headers
    page = response.content.decode()
    assert re.search(r"<title>\s*Layout check\s*</title>", page)
    assert re.search(r'<main id="main" tabindex="-1">\s*<h1>Layout check</h1>', page)
    assert re.search(r'<div role="status">\s*<p>Saved &lt;b&gt;ok&lt;/b&gt;</p>', page)


def test_allauth_is_the_login_backend():
    assert settings.AUTHENTICATION_BACKENDS == [
        "axes.backends.AxesStandaloneBackend",
        "allauth.account.auth_backends.AuthenticationBackend",
        "django.contrib.auth.backends.ModelBackend",
    ]


def test_the_chosen_user_model_is_in_use():
    expected = "email_users.User" if EMAIL_USERS else "auth.User"
    assert get_user_model()._meta.label == expected


@pytest.mark.parametrize("value", ["", "Email", " email", "custom", "auth.User"])
def test_an_unknown_user_model_choice_is_refused(monkeypatch, value):
    monkeypatch.setenv("TEST_USER_MODEL", value)
    with pytest.raises(ImproperlyConfigured, match="TEST_USER_MODEL must be one of"):
        runpy.run_path(str(SETTINGS_FILE))


@pytest.mark.django_db
def test_a_user_can_log_in_through_allauth():
    get_user_model().objects.create_user(username="ada", email="ada@example.com", password=PASSWORD)
    request = RequestFactory().post(ADMIN_LOGIN)
    assert authenticate(request, username="ada", password=PASSWORD)
    assert authenticate(request, username="ada", password=PASSWORD + "-wrong") is None


@email_users_only
@pytest.mark.django_db
def test_the_capy_project_user_stores_emails_lowercase():
    users = get_user_model().objects
    users.create_user(username="ada", email=" Ada@Example.com ", password=PASSWORD)
    assert users.get(username="ada").email == "ada@example.com"


@email_users_only
@pytest.mark.django_db
def test_the_database_refuses_emails_differing_only_in_case():
    # update() skips save()'s lowercasing, so only the database's rule can refuse it.
    users = get_user_model().objects
    users.create_user(username="ada", email="ada@example.com", password=PASSWORD)
    users.create_user(username="bob", email="bob@example.com", password=PASSWORD)
    with pytest.raises(IntegrityError), transaction.atomic():
        users.filter(username="bob").update(email="ADA@EXAMPLE.COM")


@email_users_only
@pytest.mark.django_db
def test_the_capy_project_user_migrations_are_up_to_date():
    output = StringIO()
    try:
        call_command(
            "makemigrations", "email_users", "--check", "--dry-run", stdout=output, stderr=output
        )
    except SystemExit:
        pytest.fail(f"Missing email_users migrations (see the README):\n{output.getvalue()}")
