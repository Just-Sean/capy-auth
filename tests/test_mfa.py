"""Two-step sign-in: setting up an authenticator app (codes from tests/totp.py, as a
real app makes them), signing in with a code, recovery codes (each usable once), the
secrets stored only encrypted, the encryption key (changing it, re-encrypting), the
warning email after repeated wrong codes, the pages' hints, the startup checks and the
settings page's status line."""

import ast
import html
import importlib
import re
from io import StringIO
from pathlib import Path

import pytest
from allauth.mfa.models import Authenticator
from cryptography.fernet import Fernet
from django.apps import apps as django_apps
from django.core import mail
from django.core.management import call_command
from django.template.loader import render_to_string
from django.test import Client
from django.urls import reverse

from capy_auth.mfa import checks as checks_module
from capy_auth.mfa import crypto
from capy_auth.mfa.checks import (
    KEY_HINT,
    check_encryption_keys,
    check_encryption_keys_for_deploy,
    check_mfa_setup,
)
from capy_auth.mfa.services import reencrypted
from tests import totp
from tests.accounts import ACCOUNT_PAGE, PASSWORD, log_in
from tests.helpers import check_page

MFA_PAGE = reverse("mfa_index")
ACTIVATE = reverse("mfa_activate_totp")
DEACTIVATE = reverse("mfa_deactivate_totp")
RECOVERY_CODES = reverse("mfa_view_recovery_codes")
AUTHENTICATE = reverse("mfa_authenticate")
REAUTHENTICATE = reverse("account_reauthenticate")
SECRET = re.compile(r"\b[A-Z2-7]{32}\b")


def at_code_step():
    client = Client()
    assert log_in(client).url == AUTHENTICATE
    return client


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
    with pytest.raises(crypto.SecretUnreadable):
        crypto.decrypt(stored)


def test_keys_can_come_as_one_comma_separated_value(settings):
    one, two = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    settings.CAPY_AUTH_ENCRYPTION_KEYS = f" {one}, {two} "
    assert crypto.configured_keys() == [one, two]


def test_the_hint_gives_both_command_forms_and_the_backup_advice():
    assert "uv run python -c" in KEY_HINT
    assert "docker compose -f compose.yaml -f compose.prod.yaml run --rm --no-deps web" in KEY_HINT
    assert "not with the database backup" in KEY_HINT


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
    ("keys", "debug", "says"),
    [
        ("configured", False, "Set up: encrypted with the key in CAPY_AUTH_ENCRYPTION_KEYS"),
        ("two", False, "the first of 2 keys in CAPY_AUTH_ENCRYPTION_KEYS"),
        ("none", True, "A development-only key is in use"),
        ("none", False, "Not working: CAPY_AUTH_ENCRYPTION_KEYS isn't set"),
        ("bad", False, "Not working: key 1 of CAPY_AUTH_ENCRYPTION_KEYS"),
    ],
)
def test_the_settings_page_shows_the_keys_state_never_the_key(
    settings, superuser_client, keys, debug, says
):
    settings.DEBUG = debug
    settings.CAPY_AUTH_ENCRYPTION_KEYS = {
        "configured": settings.CAPY_AUTH_ENCRYPTION_KEYS,
        "two": [Fernet.generate_key().decode(), Fernet.generate_key().decode()],
        "none": [],
        "bad": ["not-a-key"],
    }[keys]
    page = superuser_client.get(
        reverse("admin:capy_auth_authsettings_changelist"), follow=True
    ).content.decode()
    assert says in html.unescape(page)
    assert "back it up" not in page  # admins may not run the server: no backup prompt
    for key in settings.CAPY_AUTH_ENCRYPTION_KEYS:
        assert key not in page


@pytest.mark.django_db
def test_people_without_two_step_sign_in_arent_asked_for_a_code(client, ada):
    assert log_in(client).url == ACCOUNT_PAGE


# --- The pages ------------------------------------------------------------------------


@pytest.mark.django_db
def test_code_fields_say_which_code_and_show_a_number_pad(with_app):
    page = check_page(at_code_step().get(AUTHENTICATE))
    assert "The 6-digit code from your authenticator app, or one of your recovery" in page
    assert "email we sent you" not in page
    assert 'inputmode="numeric"' in page and "autocapitalize" not in page
    assert "Lost your phone? Enter one of your recovery codes instead." in page


@pytest.mark.django_db
def test_email_code_fields_keep_their_own_hint(client):
    response = client.post(
        reverse("account_signup"),
        {"email": "eve@example.com", "password1": PASSWORD, "password2": PASSWORD},
    )
    page = check_page(client.get(response.url))
    assert "The code from the email we sent you" in page
    assert 'autocapitalize="characters"' in page and "inputmode" not in page


@pytest.mark.django_db
def test_the_setup_page_shows_the_qr_on_white_and_a_key_to_copy(client, ada):
    response = confirmed(client).get(ACTIVATE)
    page = check_page(response)
    assert '<div class="w-fit rounded-box bg-white p-3">' in page
    assert 'alt="QR code to scan with your authenticator app"' in page
    assert re.search(r'id="authenticator_secret">([A-Z2-7]{4} ){7}[A-Z2-7]{4}<', page)
    assert 'href="otpauth://totp/' in page
    assert "no-store" in response["Cache-Control"]  # the secret isn't cached


def test_the_keys_never_appear_in_error_reports():
    for function in (
        crypto.configured_keys,
        crypto.keys_in_use,
        crypto.stand_in_key,
        crypto.encrypt,
        crypto.decrypt,
        crypto.reencrypt,
    ):
        assert getattr(function, "sensitive_variables", None) == "__ALL__", function


# --- Warnings when the code step keeps failing --------------------------------------------


@pytest.mark.django_db
def test_the_owner_is_emailed_after_five_wrong_codes(with_app):
    mail.outbox.clear()
    for _ in range(4):
        at_code_step().post(AUTHENTICATE, {"code": "000000"})
    assert mail.outbox == []
    at_code_step().post(AUTHENTICATE, {"code": "000000"})
    assert [m.subject.split("] ", 1)[-1] for m in mail.outbox] == [
        "Someone tried to sign in to your account"
    ]
    assert mail.outbox[0].to == ["ada@example.com"]
    at_code_step().post(AUTHENTICATE, {"code": "000000"})
    assert len(mail.outbox) == 1  # once, not for every further try


@pytest.mark.django_db
def test_a_right_code_resets_the_count(with_app):
    secret, _ = with_app
    for _ in range(4):
        at_code_step().post(AUTHENTICATE, {"code": "000000"})
    sign_in_with(totp.code(secret))
    mail.outbox.clear()
    for _ in range(4):
        at_code_step().post(AUTHENTICATE, {"code": "000000"})
    assert mail.outbox == []


# --- Changing keys ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_reencrypting_lets_the_old_key_go(settings, with_app):
    secret, codes = with_app
    old = settings.CAPY_AUTH_ENCRYPTION_KEYS[0]
    new = Fernet.generate_key().decode()
    settings.CAPY_AUTH_ENCRYPTION_KEYS = [new, old]
    out = StringIO()
    call_command("capy_auth_reencrypt", stdout=out)
    assert "Re-encrypted 2 authenticators." in out.getvalue()
    assert "older keys can be dropped" in out.getvalue()
    settings.CAPY_AUTH_ENCRYPTION_KEYS = [new]
    assert sign_in_with(totp.code(secret)).get(ACCOUNT_PAGE).status_code == 200
    assert sign_in_with(codes[0]).get(ACCOUNT_PAGE).status_code == 200


@pytest.mark.django_db
def test_reencrypting_reports_secrets_no_key_can_read(settings, with_app):
    settings.CAPY_AUTH_ENCRYPTION_KEYS = [Fernet.generate_key().decode()]
    out = StringIO()
    call_command("capy_auth_reencrypt", stdout=out)
    assert "Re-encrypted 0 authenticators." in out.getvalue()
    assert "2 couldn't be read" in out.getvalue()


@pytest.mark.django_db
def test_reencrypting_covers_migrated_recovery_codes(settings, ada):
    stored = crypto.encrypt("12345678")
    authenticator = Authenticator.objects.create(
        user=ada,
        type="recovery_codes",
        data={"seed": crypto.encrypt("s"), "migrated_codes": [stored]},
    )
    new = Fernet.generate_key().decode()
    settings.CAPY_AUTH_ENCRYPTION_KEYS = [new, *settings.CAPY_AUTH_ENCRYPTION_KEYS]
    call_command("capy_auth_reencrypt", stdout=StringIO())
    settings.CAPY_AUTH_ENCRYPTION_KEYS = [new]
    authenticator.refresh_from_db()
    assert crypto.decrypt(authenticator.data["migrated_codes"][0]) == "12345678"


# --- Startup checks in production ------------------------------------------------------------


def test_check_deploy_needs_a_real_key_even_with_debug_left_on(settings):
    settings.DEBUG = True
    settings.CAPY_AUTH_ENCRYPTION_KEYS = []
    assert [e.id for e in check_encryption_keys_for_deploy(None)] == ["capy_auth.E007"]
    settings.DEBUG = False  # the normal check reports it then
    assert check_encryption_keys_for_deploy(None) == []
    settings.DEBUG = True
    settings.CAPY_AUTH_ENCRYPTION_KEYS = ["not-a-key"]  # the normal check reports it
    assert check_encryption_keys_for_deploy(None) == []
    settings.CAPY_AUTH_ENCRYPTION_KEYS = [Fernet.generate_key().decode()]
    assert check_encryption_keys_for_deploy(None) == []


def test_without_allauths_mfa_app_the_check_says_so_instead_of_crashing(monkeypatch):
    """Without the app, importing allauth's MFA code crashes; the checks module must
    not do that when it loads, and the check must stop before reaching it."""
    source = Path(checks_module.__file__).read_text(encoding="utf-8")
    top_level = [node for node in ast.parse(source).body if isinstance(node, ast.ImportFrom)]
    assert not [node.module for node in top_level if node.module in ("adapter", "allauth.mfa")]
    assert all("mfa" not in (node.module or "") for node in top_level if node.level == 0)
    monkeypatch.setattr(checks_module.apps, "is_installed", lambda name: False)
    monkeypatch.setattr(checks_module, "uses_capy_auth_adapter", lambda: pytest.fail("imported"))
    assert [e.id for e in check_mfa_setup(None)] == ["capy_auth.E008"]


def test_without_allauths_mfa_app_capy_auth_loads_none_of_it(monkeypatch):
    import capy_auth.urls

    installed = django_apps.is_installed
    monkeypatch.setattr(
        django_apps, "is_installed", lambda name: name != "allauth.mfa" and installed(name)
    )
    try:
        django_apps.get_app_config("capy_auth").ready()  # connects nothing for MFA
        urls = importlib.reload(capy_auth.urls)
        assert "mfa_activate_totp" not in [getattr(p, "name", None) for p in urls.urlpatterns]
    finally:
        monkeypatch.undo()
        importlib.reload(capy_auth.urls)


@pytest.mark.django_db
def test_wrong_codes_while_confirming_a_change_dont_send_the_warning(with_app):
    client = sign_in_with(with_app[1][0])
    mail.outbox.clear()
    for _ in range(5):
        client.post(reverse("mfa_reauthenticate"), {"code": "000000"})
    assert mail.outbox == []


def test_an_authenticator_without_its_secret_is_left_as_it_is():
    assert reencrypted("totp", {}) == {}
    assert reencrypted("webauthn", {"credential": "x"}) == {"credential": "x"}


# --- The pages in capy-auth's words -------------------------------------------------------


def signed_in_with_app(with_app):
    client = sign_in_with(with_app[1][0])
    client.post(REAUTHENTICATE, {"password": PASSWORD})
    return client


@pytest.mark.django_db
def test_the_overview_says_whats_on_and_offers_a_way_back(client, ada):
    log_in(client)
    page = check_page(client.get(MFA_PAGE))
    assert "<title>" in page and "Two-step sign-in" in page
    assert "Off: set up an app" in page
    assert f'href="{ACTIVATE}"' in page
    assert f'href="{ACCOUNT_PAGE}"' in page


@pytest.mark.django_db
def test_with_an_app_the_overview_offers_turning_off_and_the_codes(with_app):
    page = check_page(signed_in_with_app(with_app).get(MFA_PAGE))
    assert "On: signing in asks for the code" in page
    assert "9 of 10 codes left" in page
    for name in ("mfa_deactivate_totp", "mfa_view_recovery_codes", "mfa_download_recovery_codes"):
        assert f'href="{reverse(name)}"' in page
    assert "Make new codes" in page


@pytest.mark.django_db
def test_turning_off_says_what_it_removes_and_offers_keeping_it(with_app):
    page = check_page(signed_in_with_app(with_app).get(DEACTIVATE))
    assert "stop asking for codes from your authenticator app" in page
    assert "If you have no passkey or security key, your recovery codes are deleted" in page
    assert f'href="{MFA_PAGE}"' in page and "Keep it on" in page


@pytest.mark.django_db
def test_the_codes_page_says_what_theyre_for_and_how_to_leave(with_app):
    page = check_page(signed_in_with_app(with_app).get(RECOVERY_CODES))
    assert "Each works once. Keep them somewhere safe" in page
    assert f'href="{reverse("mfa_download_recovery_codes")}"' in page
    assert f'href="{MFA_PAGE}"' in page and ">Done<" in page


@pytest.mark.django_db
def test_making_new_codes_warns_about_the_old_ones_and_offers_a_way_back(with_app):
    page = check_page(signed_in_with_app(with_app).get(reverse("mfa_generate_recovery_codes")))
    assert "your old codes will stop working" in page
    assert f'href="{MFA_PAGE}"' in page


@pytest.mark.django_db
def test_the_codes_page_makes_download_the_main_action_and_says_how_to_copy(with_app):
    page = check_page(signed_in_with_app(with_app).get(RECOVERY_CODES))
    download = reverse("mfa_download_recovery_codes")
    assert f'href="{download}"\nclass="btn btn-primary"' in page.replace('" class', '"\nclass')
    assert "btn-outline" in page  # making new codes is the quieter choice
    assert "Click the box to copy them" in page
    assert 'aria-describedby="recovery_codes_helptext' in page
    assert "font-mono" in page


@pytest.mark.django_db
def test_with_codes_shown_once_the_pages_hide_seeing_them_again(settings, ada):
    settings.MFA_RECOVERY_CODES_SHOW_ONCE = True
    client = confirmed(Client())
    set_up_app(client)
    first = check_page(client.get(RECOVERY_CODES))
    assert 'id="codes_saved"' in first  # "I've saved my recovery codes"
    overview = check_page(client.get(MFA_PAGE))
    assert f'href="{RECOVERY_CODES}"' not in overview
    assert "Make new codes" in overview


@pytest.mark.django_db
def test_making_new_codes_with_none_left_is_the_main_action(settings, ada):
    settings.MFA_RECOVERY_CODE_COUNT = 1
    client = confirmed(Client())
    set_up_app(client)
    [code] = recovery_codes(client)
    client = sign_in_with(code)  # the only code, now used
    client.post(REAUTHENTICATE, {"password": PASSWORD})
    page = check_page(client.get(reverse("mfa_generate_recovery_codes")))
    assert "old codes will stop working" not in page
    assert 'type="submit"' in page and "btn btn-primary" in page and "btn-error" not in page


@pytest.mark.django_db
def test_turning_it_off_deletes_the_app_and_the_codes_and_says_so(
    with_app, ada, django_capture_on_commit_callbacks
):
    client = signed_in_with_app(with_app)
    with django_capture_on_commit_callbacks(execute=True):
        response = client.post(DEACTIVATE, follow=True)
    assert not Authenticator.objects.filter(user=ada).exists()
    assert "Your authenticator app no longer gives sign-in codes" in check_page(response)


@pytest.mark.parametrize(
    ("message", "show_once", "says"),
    [
        ("totp_activated", False, "Two-step sign-in is on"),
        ("recovery_codes_generated", False, "New recovery codes made"),
        ("recovery_codes_generated", True, "They won’t be shown again."),
    ],
)
def test_the_confirmations_are_in_capy_auths_words(message, show_once, says):
    """allauth adds these once the change is saved (after the request, in tests), so the
    message templates are checked directly."""
    text = render_to_string(
        f"mfa/messages/{message}.txt", {"MFA_RECOVERY_CODES_SHOW_ONCE": show_once}
    )
    assert says in text
