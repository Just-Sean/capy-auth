"""Two-step sign-in: setting up an authenticator app (codes from tests/totp.py, as a
real app makes them), signing in with a code, recovery codes shown once and each usable
once, the secrets stored only encrypted, the encryption key (changing it, losing it),
the startup checks and the settings page's status line."""

import re

import pytest
from allauth.mfa.models import Authenticator
from cryptography.fernet import Fernet
from django.core.exceptions import ImproperlyConfigured
from django.test import Client
from django.urls import reverse

from capy_auth.mfa import crypto
from capy_auth.mfa.checks import check_encryption_keys, check_mfa_setup
from tests import totp
from tests.accounts import ACCOUNT_PAGE, LOGIN, PASSWORD, log_in
from tests.helpers import check_page

MFA_PAGE = reverse("mfa_index")
ACTIVATE = reverse("mfa_activate_totp")
DEACTIVATE = reverse("mfa_deactivate_totp")
RECOVERY_CODES = reverse("mfa_view_recovery_codes")
AUTHENTICATE = reverse("mfa_authenticate")
REAUTHENTICATE = reverse("account_reauthenticate")
SECRET = re.compile(r"\b[A-Z2-7]{32}\b")


def confirmed(client):
    """Signed in as Ada, who has just typed her password again (MFA changes ask)."""
    log_in(client)
    client.post(REAUTHENTICATE, {"password": PASSWORD})
    return client


def set_up_app(client):
    """Sets up an authenticator app; returns its secret (as the app would store it)."""
    page = check_page(client.get(ACTIVATE))
    secret = SECRET.search(page).group(0)
    response = client.post(ACTIVATE, {"code": totp.code(secret)})
    assert response.status_code == 302
    return secret


def recovery_codes(client):
    page = check_page(client.get(RECOVERY_CODES))
    return re.findall(r"\b[0-9a-f]{8}\b", page)


@pytest.fixture
def with_app(ada):
    client = confirmed(Client())
    secret = set_up_app(client)
    codes = recovery_codes(client)
    return secret, codes


# --- Setting it up ---------------------------------------------------------------------


@pytest.mark.django_db
def test_the_account_page_links_to_two_step_sign_in(client, ada):
    log_in(client)
    assert f'href="{MFA_PAGE}"' in check_page(client.get(ACCOUNT_PAGE))
    check_page(client.get(MFA_PAGE))


@pytest.mark.django_db
def test_setting_up_asks_for_the_password_again(client, ada):
    log_in(client)
    assert client.get(ACTIVATE).url.startswith(REAUTHENTICATE)


@pytest.mark.django_db
def test_the_setup_page_shows_a_qr_code_and_the_key(client, ada):
    page = check_page(confirmed(client).get(ACTIVATE))
    assert 'src="data:image/svg+xml;base64,' in page
    assert SECRET.search(page)


@pytest.mark.django_db
def test_a_wrong_code_doesnt_set_it_up(client, ada):
    confirmed(client).get(ACTIVATE)
    page = client.post(ACTIVATE, {"code": "000000"})
    assert page.status_code == 200
    assert not Authenticator.objects.exists()


@pytest.mark.django_db
def test_the_database_holds_only_encrypted_secrets(with_app):
    secret, codes = with_app
    stored = {a.type: a.data for a in Authenticator.objects.all()}
    assert set(stored) == {"totp", "recovery_codes"}
    assert secret not in str(stored)
    assert crypto.decrypt(stored["totp"]["secret"]) == secret
    assert stored["recovery_codes"]["seed"] != crypto.decrypt(stored["recovery_codes"]["seed"])


# --- Signing in ---------------------------------------------------------------------------


def sign_in_with(code):
    client = Client()
    response = log_in(client)
    assert response.url == AUTHENTICATE  # asks for a code before letting anyone in
    assert client.get(ACCOUNT_PAGE).status_code == 302
    check_page(client.get(AUTHENTICATE))
    client.post(AUTHENTICATE, {"code": code})
    return client


@pytest.mark.django_db
def test_signing_in_asks_for_a_code_and_the_apps_code_lets_you_in(with_app):
    secret, _ = with_app
    assert sign_in_with(totp.code(secret)).get(ACCOUNT_PAGE).status_code == 200


@pytest.mark.django_db
def test_a_wrong_code_doesnt_let_you_in(with_app):
    assert sign_in_with("123456").get(ACCOUNT_PAGE).status_code == 302


@pytest.mark.django_db
def test_an_apps_code_works_only_once(with_app):
    secret, _ = with_app
    code = totp.code(secret)
    assert sign_in_with(code).get(ACCOUNT_PAGE).status_code == 200
    assert sign_in_with(code).get(ACCOUNT_PAGE).status_code == 302


@pytest.mark.django_db
def test_a_recovery_code_works_only_once(with_app):
    _, codes = with_app
    assert len(codes) == 10
    assert sign_in_with(codes[0]).get(ACCOUNT_PAGE).status_code == 200
    assert sign_in_with(codes[0]).get(ACCOUNT_PAGE).status_code == 302
    assert sign_in_with(codes[1]).get(ACCOUNT_PAGE).status_code == 200


@pytest.mark.django_db
def test_recovery_codes_are_shown_once(with_app):
    client = sign_in_with(with_app[1][0])
    client.post(REAUTHENTICATE, {"password": PASSWORD})
    page = check_page(client.get(RECOVERY_CODES))
    assert "9 out of 10 recovery codes" in page
    assert not set(with_app[1]) & set(re.findall(r"\b[0-9a-f]{8}\b", page))  # seen at setup


@pytest.mark.django_db
def test_turning_it_off_asks_again_and_signing_in_no_longer_asks_for_a_code(ada, with_app):
    client = Client()
    log_in(client)
    client.post(AUTHENTICATE, {"code": with_app[1][0]})
    assert client.post(DEACTIVATE).url.startswith(REAUTHENTICATE)
    client.post(REAUTHENTICATE, {"password": PASSWORD})
    assert client.post(DEACTIVATE).status_code == 302
    assert not Authenticator.objects.filter(type="totp").exists()
    assert log_in(Client()).url == ACCOUNT_PAGE


# --- The key -------------------------------------------------------------------------------


def test_a_new_key_put_first_still_reads_what_the_old_one_wrote(settings):
    old = settings.CAPY_AUTH_ENCRYPTION_KEYS[0]
    stored = crypto.encrypt("JBSWY3DPEHPK3PXP")
    new = Fernet.generate_key().decode()
    settings.CAPY_AUTH_ENCRYPTION_KEYS = [new, old]
    assert crypto.decrypt(stored) == "JBSWY3DPEHPK3PXP"
    settings.CAPY_AUTH_ENCRYPTION_KEYS = [new]  # the old key dropped too soon
    with pytest.raises(ImproperlyConfigured, match="isn't in the list any more"):
        crypto.decrypt(stored)


def test_keys_can_come_as_one_comma_separated_value(settings):
    one, two = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    settings.CAPY_AUTH_ENCRYPTION_KEYS = f" {one}, {two} "
    assert crypto.configured_keys() == [one, two]


def test_development_without_a_key_uses_a_stand_in_and_says_so(settings):
    settings.CAPY_AUTH_ENCRYPTION_KEYS = None
    settings.DEBUG = True
    assert crypto.decrypt(crypto.encrypt("secret")) == "secret"
    warnings = check_encryption_keys(None)
    assert [w.id for w in warnings] == ["capy_auth.W005"]
    assert "Fernet.generate_key()" in warnings[0].hint
    assert "back it up" in warnings[0].hint


@pytest.mark.parametrize("value", [None, [], ""])
def test_production_without_a_key_doesnt_start(settings, value):
    settings.CAPY_AUTH_ENCRYPTION_KEYS = value
    errors = check_encryption_keys(None)
    assert [e.id for e in errors] == ["capy_auth.E007"]
    assert "isn't set" in errors[0].msg
    assert "Fernet.generate_key()" in errors[0].hint
    with pytest.raises(crypto.KeyProblem):
        crypto.encrypt("secret")


@pytest.mark.parametrize("debug", [True, False])
def test_a_malformed_key_is_an_error_everywhere(settings, debug):
    settings.DEBUG = debug
    settings.CAPY_AUTH_ENCRYPTION_KEYS = ["not-a-key"]
    errors = check_encryption_keys(None)
    assert [e.id for e in errors] == ["capy_auth.E007"]
    assert "key 1 of CAPY_AUTH_ENCRYPTION_KEYS isn't a valid key" in errors[0].msg


def test_the_stand_in_project_passes_the_mfa_checks():
    assert check_encryption_keys(None) == []
    assert check_mfa_setup(None) == []


@pytest.mark.parametrize(
    "adapter",
    ["allauth.mfa.adapter.DefaultMFAAdapter", "tests.no_such.Adapter", "tests.totp.code"],
)
def test_without_capy_auths_mfa_adapter_the_site_doesnt_start(settings, adapter):
    settings.MFA_ADAPTER = adapter
    assert [e.id for e in check_mfa_setup(None)] == ["capy_auth.E008"]


# --- The settings page ------------------------------------------------------------------


@pytest.fixture
def superuser_client(db):
    from django.contrib.auth import get_user_model

    superuser = get_user_model().objects.create_superuser(
        username="admin", email="admin@example.com", password=PASSWORD
    )
    client = Client()
    client.force_login(superuser)
    return client


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("keys", "says"),
    [
        ("configured", "Encrypted with the key in CAPY_AUTH_ENCRYPTION_KEYS"),
        ("two", "(2 keys; the first encrypts)"),
        ("none", "A development-only key is in use"),
        ("bad", "Not working: key 1 of CAPY_AUTH_ENCRYPTION_KEYS"),
    ],
)
def test_the_settings_page_shows_the_keys_state_never_the_key(
    settings, superuser_client, keys, says
):
    settings.CAPY_AUTH_ENCRYPTION_KEYS = {
        "configured": settings.CAPY_AUTH_ENCRYPTION_KEYS,
        "two": [Fernet.generate_key().decode(), Fernet.generate_key().decode()],
        "none": [],
        "bad": ["not-a-key"],
    }[keys]
    page = superuser_client.get(
        reverse("admin:capy_auth_authsettings_changelist"), follow=True
    ).content.decode()
    assert says in page
    for key in settings.CAPY_AUTH_ENCRYPTION_KEYS:
        assert key not in page


@pytest.mark.django_db
def test_signing_in_page_still_works_for_people_without_mfa(client, ada):
    assert log_in(client).url == ACCOUNT_PAGE
    assert client.get(LOGIN).status_code in (200, 302)
