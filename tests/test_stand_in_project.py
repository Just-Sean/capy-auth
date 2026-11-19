"""The stand-in project gives the module what a capy project gives it: allauth, the strict
Content Security Policy, layout.html with its messages region, and the user model being
tested (Django's default, or a capy-project user with TEST_USER_MODEL=email)."""

import secrets

import pytest
from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from django.db import IntegrityError, transaction
from django.template import Context, Template
from django.test import RequestFactory

ADMIN_LOGIN = "/admin/login/"
EMAIL_USERS = settings.TEST_USER_MODEL == "email"
PASSWORD = secrets.token_urlsafe()  # made each run, so no password is written here


def test_pages_get_the_strict_policy(client):
    policy = client.get(ADMIN_LOGIN).headers["Content-Security-Policy"]
    assert "default-src 'none'" in policy
    assert "script-src 'self' 'nonce-" in policy
    assert "style-src 'self' 'nonce-" in policy
    assert "form-action 'self'" in policy


def test_layout_gives_pages_their_blocks_and_the_messages_region():
    page = Template(
        '{% extends "layout.html" %}'
        "{% block title %}Log in{% endblock %}"
        "{% block content %}<h1>Log in</h1>{% endblock %}"
    ).render(Context({"messages": ["Saved."]}))
    assert "<title>Log in</title>" in page
    assert '<main id="main" tabindex="-1">\n    <h1>Log in</h1>' in page
    assert '<div role="status">\n    <p>Saved.</p>' in page


def test_allauth_is_the_login_backend():
    assert settings.AUTHENTICATION_BACKENDS == [
        "allauth.account.auth_backends.AuthenticationBackend"
    ]


def test_the_chosen_user_model_is_in_use():
    expected = "email_users.User" if EMAIL_USERS else "auth.User"
    assert get_user_model()._meta.label == expected


@pytest.mark.django_db
def test_a_user_can_log_in_through_allauth():
    get_user_model().objects.create_user(username="ada", email="ada@example.com", password=PASSWORD)
    request = RequestFactory().post(ADMIN_LOGIN)
    assert authenticate(request, username="ada", password=PASSWORD)
    assert authenticate(request, username="ada", password=PASSWORD + "-wrong") is None


@pytest.mark.skipif(not EMAIL_USERS, reason="only the capy-project user model has these rules")
@pytest.mark.django_db
def test_the_capy_project_user_keeps_emails_lowercase_and_unique():
    users = get_user_model().objects
    users.create_user(username="ada", email=" Ada@Example.com ", password=PASSWORD)
    assert users.get(username="ada").email == "ada@example.com"
    with pytest.raises(IntegrityError), transaction.atomic():
        users.create_user(username="ada2", email="ADA@example.com", password=PASSWORD)
