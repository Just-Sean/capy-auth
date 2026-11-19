"""capy-auth's warnings: W001 for allauth settings that weaken its security choices,
W002 for a cache the background worker can't share. A project set up as the README says
gets neither."""

import pytest

from capy_auth.config.checks import check_email_queue, check_security_settings

SEPARATE_WORKER = {"default": {"BACKEND": "django_tasks_db.DatabaseBackend"}}


def warned_settings():
    return [warning.msg.split()[0] for warning in check_security_settings(None)]


def test_a_project_set_up_as_the_readme_says_gets_no_warning():
    assert warned_settings() == []


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("ACCOUNT_LOGIN_METHODS", {"email", "username"}),
        ("ACCOUNT_EMAIL_VERIFICATION", "optional"),
        ("ACCOUNT_EMAIL_VERIFICATION_BY_CODE_ENABLED", False),
        ("ACCOUNT_PREVENT_ENUMERATION", False),
        ("ACCOUNT_REAUTHENTICATION_REQUIRED", False),
        ("PASSWORD_RESET_TIMEOUT", 60 * 60 * 24),
    ],
)
def test_a_weaker_setting_gets_a_warning(settings, name, value):
    setattr(settings, name, value)
    assert warned_settings() == [name]


def test_behind_a_proxy_the_proxy_count_is_needed(settings):
    settings.SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    assert warned_settings() == ["ALLAUTH_TRUSTED_PROXY_COUNT"]
    settings.ALLAUTH_TRUSTED_PROXY_COUNT = 1
    assert warned_settings() == []


def test_a_trusted_client_ip_header_also_does_behind_a_proxy(settings):
    settings.SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    settings.ALLAUTH_TRUSTED_CLIENT_IP_HEADER = "X-Real-IP"
    assert warned_settings() == []


def test_jobs_run_at_once_need_no_shared_cache():
    assert check_email_queue(None) == []


@pytest.mark.parametrize(
    "cache_backend",
    [
        "django.core.cache.backends.locmem.LocMemCache",
        "django.core.cache.backends.dummy.DummyCache",
        "django.core.cache.backends.db.DatabaseCache",
        "django.core.cache.backends.filebased.FileBasedCache",
    ],
)
def test_a_separate_worker_with_a_cache_it_cant_share_gets_a_warning(settings, cache_backend):
    settings.TASKS = SEPARATE_WORKER
    settings.CACHES = {"default": {"BACKEND": cache_backend}}
    assert [warning.id for warning in check_email_queue(None)] == ["capy_auth.W002"]


def test_a_separate_worker_with_redis_is_fine(settings):
    settings.TASKS = SEPARATE_WORKER
    settings.CACHES = {"default": {"BACKEND": "django.core.cache.backends.redis.RedisCache"}}
    assert check_email_queue(None) == []
