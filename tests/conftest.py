"""Shared test setup."""

import pytest
from django.core.cache import cache


@pytest.fixture(autouse=True)
def fresh_rate_limits():
    """allauth counts attempts (signups, logins, resets) in the cache; start each test
    with none counted, so one test's attempts never trip another's limit."""
    cache.clear()
    yield
    cache.clear()
