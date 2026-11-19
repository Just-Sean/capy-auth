"""Shared test setup."""

import pytest
from allauth.account.models import EmailAddress
from django.contrib.auth import get_user_model
from django.core.cache import cache

from tests.accounts import PASSWORD


@pytest.fixture(autouse=True)
def fresh_rate_limits():
    """allauth counts attempts (signups, logins, resets) in the cache; start each test
    with none counted, so one test's attempts never trip another's limit."""
    cache.clear()


@pytest.fixture
def ada():
    """A user with a verified email, who can log in."""
    user = get_user_model().objects.create_user(
        username="ada", email="ada@example.com", password=PASSWORD
    )
    EmailAddress.objects.create(user=user, email=user.email, primary=True, verified=True)
    return user
