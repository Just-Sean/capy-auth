"""Shared test setup."""

import pytest
from allauth.account.models import EmailAddress
from django.contrib.auth import get_user_model
from django.core.cache import cache

from capy_auth.passwords import breached
from tests.accounts import PASSWORD

# Have I Been Pwned's answer for any prefix, in tests: padding lines only (count 0), so
# no password is found and nothing goes over the network.
NOTHING_BREACHED = "0018A45C4D1DEF81644B54AB7F969B88D65:0\r\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:0"


@pytest.fixture(autouse=True)
def fresh_rate_limits():
    """allauth counts attempts (signups, logins, resets) in the cache; start each test
    with none counted, so one test's attempts never trip another's limit."""
    cache.clear()


@pytest.fixture(autouse=True)
def no_real_breach_service(monkeypatch):
    """Tests never call the real Have I Been Pwned; test_breached_passwords.py fakes it."""
    monkeypatch.setattr(breached, "fetch_range", lambda prefix: NOTHING_BREACHED)


@pytest.fixture
def ada():
    """A user with a verified email, who can log in."""
    user = get_user_model().objects.create_user(
        username="ada", email="ada@example.com", password=PASSWORD
    )
    EmailAddress.objects.create(user=user, email=user.email, primary=True, verified=True)
    return user
