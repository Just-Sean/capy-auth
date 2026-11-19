"""capy-auth's warning (capy_auth.W001) for allauth settings that weaken its security
choices: a project set up as the README says gets none."""

import pytest

from capy_auth.config.checks import check_security_settings


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
