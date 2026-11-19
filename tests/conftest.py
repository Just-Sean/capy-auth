"""Shared test setup."""

import pytest
from allauth.account.models import EmailAddress
from django.contrib.auth import get_user_model
from django.core.cache import cache

from capy_auth.passwords import breached
from tests.accounts import PASSWORD
from tests.hibp import HibpStandIn


@pytest.fixture(autouse=True)
def fresh_rate_limits():
    """allauth counts attempts (signups, logins, resets) in the cache; start each test
    with none counted, so one test's attempts never trip another's limit."""
    cache.clear()


@pytest.fixture(autouse=True)
def no_real_breach_service(monkeypatch):
    """Tests never reach the real Have I Been Pwned: its connection is a stand-in that
    answers every prefix with padding only (no password found)."""
    HibpStandIn.made = []
    HibpStandIn.response = None
    monkeypatch.setattr(breached, "HTTPSConnection", HibpStandIn)


@pytest.fixture
def ada():
    """A user with a verified email, who can log in."""
    user = get_user_model().objects.create_user(
        username="ada", email="ada@example.com", password=PASSWORD
    )
    EmailAddress.objects.create(user=user, email=user.email, primary=True, verified=True)
    return user
