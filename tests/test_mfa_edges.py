"""Edge cases for two-step sign-in: codes at time-step edges, spaces, reuse, the
wrong-code limit, recovery codes made again and downloaded, the key changing or getting
lost, malformed key lists, bans and password resets."""

import re
import time

import pytest
from allauth.mfa.models import Authenticator
from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.core import mail
from django.test import Client
from django.urls import reverse

from capy_auth.bans.models import BannedEmail
from capy_auth.bans.services import lift_bans, suspend_accounts
from capy_auth.mfa import crypto
from capy_auth.mfa.checks import check_encryption_keys
from tests import test_mfa, totp
from tests.accounts import ACCOUNT_PAGE, LOGIN, NEW_PASSWORD, PASSWORD, RESET, log_in, reset_link
from tests.helpers import check_page
from tests.test_mfa import (
    ACTIVATE,
    AUTHENTICATE,
    REAUTHENTICATE,
    RECOVERY_CODES,
    confirmed,
    recovery_codes,
    set_up_app,
    sign_in_with,
)

with_app = test_mfa.with_app  # the fixture, shared

GENERATE = reverse("mfa_generate_recovery_codes")
DOWNLOAD = reverse("mfa_download_recovery_codes")
ADMIN_LOGIN = reverse("admin:login")
ADMIN_INDEX = reverse("admin:index")


def signed_in(client):
    return client.get(ACCOUNT_PAGE).status_code == 200


def signed_in_directly(client):
    """Signing in with only the password lands on the account page (no code step)."""
    return log_in(client).url == ACCOUNT_PAGE


def at_code_step():
    client = Client()
    assert log_in(client).url == AUTHENTICATE
    return client


# --- Codes -------------------------------------------------------------------------------


@pytest.mark.django_db
def test_a_code_typed_with_a_space_in_the_middle_works(with_app):
    secret, _ = with_app
    code = totp.code(secret)
    assert signed_in(sign_in_with(f"{code[:3]} {code[3:]}"))


@pytest.mark.django_db
def test_a_code_reused_with_a_space_added_is_still_refused(with_app):
    secret, _ = with_app
    code = totp.code(secret)
    assert signed_in(sign_in_with(code))
    assert not signed_in(sign_in_with(f"{code[:3]} {code[3:]}"))


@pytest.mark.django_db
def test_a_code_from_two_steps_ago_is_refused(with_app):
    secret, _ = with_app
    assert not signed_in(sign_in_with(totp.code(secret, at=time.time() - 60)))


@pytest.mark.django_db
def test_the_previous_steps_code_still_works(with_app):
    """RFC 6238 section 5.2 recommends accepting one step back for transmission delay:
    a code read at second 29 and submitted at second 31 is otherwise refused."""
    secret, _ = with_app
    assert signed_in(sign_in_with(totp.code(secret, at=time.time() - 30)))


@pytest.mark.django_db
def test_a_recovery_code_with_spaces_or_dashes_works(with_app):
    _, codes = with_app
    assert signed_in(sign_in_with(f" {codes[0][:4]}-{codes[0][4:]} "))


@pytest.mark.django_db
def test_wrong_codes_are_limited_even_before_the_right_one(with_app):
    secret, _ = with_app
    client = at_code_step()
    for _ in range(5):
        client.post(AUTHENTICATE, {"code": "000000"})
    client.post(AUTHENTICATE, {"code": totp.code(secret)})
    assert not signed_in(client)


@pytest.mark.django_db
def test_the_wrong_code_limit_holds_across_fresh_logins(with_app):
    secret, _ = with_app
    for _ in range(5):
        at_code_step().post(AUTHENTICATE, {"code": "000000"})
    client = at_code_step()
    client.post(AUTHENTICATE, {"code": totp.code(secret)})
    assert not signed_in(client)


# --- Recovery codes ----------------------------------------------------------------------


@pytest.mark.django_db
def test_regenerating_recovery_codes_kills_the_old_ones(with_app):
    _, old = with_app
    client = sign_in_with(old[0])
    client.post(REAUTHENTICATE, {"password": PASSWORD})
    assert client.post(GENERATE).status_code == 302
    new = recovery_codes(client)
    assert len(new) == 10 and not set(new) & set(old)
    assert not signed_in(sign_in_with(old[1]))
    assert signed_in(sign_in_with(new[0]))


@pytest.mark.django_db
def test_recovery_codes_can_be_downloaded_at_setup(ada):
    client = confirmed(Client())
    set_up_app(client)
    page = client.get(RECOVERY_CODES).content.decode()
    assert f'href="{DOWNLOAD}"' in page
    response = client.get(DOWNLOAD)
    assert response.status_code == 200
    assert len(re.findall(r"\b\d{8}\b", response.content.decode())) == 10


@pytest.mark.django_db
def test_recovery_codes_can_be_seen_and_downloaded_again_after_confirming(with_app, ada):
    _, codes = with_app
    client = Client()
    client.force_login(ada)
    assert client.get(DOWNLOAD).url.startswith(REAUTHENTICATE)  # asks for the password
    client.post(REAUTHENTICATE, {"password": PASSWORD})
    assert client.get(DOWNLOAD).status_code == 200
    assert set(codes) <= set(recovery_codes(client))


@pytest.mark.django_db
def test_setting_up_twice_keeps_one_app(with_app, ada):
    client = Client()
    client.force_login(ada)
    client.post(REAUTHENTICATE, {"password": PASSWORD})
    client.get(ACTIVATE)
    assert Authenticator.objects.filter(type="totp").count() == 1


@pytest.mark.django_db
def test_turning_it_off_removes_the_recovery_codes_too(with_app, ada):
    client = Client()
    client.force_login(ada)
    client.post(REAUTHENTICATE, {"password": PASSWORD})
    client.post(reverse("mfa_deactivate_totp"))
    assert not Authenticator.objects.exists()


# --- The key -----------------------------------------------------------------------------


@pytest.mark.django_db
def test_signing_in_after_rotating_the_key_with_the_old_one_kept(settings, with_app):
    secret, codes = with_app
    settings.CAPY_AUTH_ENCRYPTION_KEYS = [
        Fernet.generate_key().decode(),
        *settings.CAPY_AUTH_ENCRYPTION_KEYS,
    ]
    assert signed_in(sign_in_with(totp.code(secret)))
    assert signed_in(sign_in_with(codes[0]))


@pytest.mark.django_db
def test_with_the_key_lost_the_code_step_says_what_to_do_and_lets_nobody_in(
    settings, with_app, caplog
):
    secret, _ = with_app
    settings.CAPY_AUTH_ENCRYPTION_KEYS = [Fernet.generate_key().decode()]
    client = Client()
    assert log_in(client).url == AUTHENTICATE
    response = client.post(AUTHENTICATE, {"code": totp.code(secret)})
    page = check_page(response, status=503)
    assert "contact the site’s staff" in page
    assert not signed_in(client)
    assert "can't be decrypted with any key in CAPY_AUTH_ENCRYPTION_KEYS" in caplog.text


@pytest.mark.django_db
def test_with_the_key_lost_staff_let_the_person_back_in(settings, with_app, ada):
    settings.CAPY_AUTH_ENCRYPTION_KEYS = [Fernet.generate_key().decode()]
    Authenticator.objects.filter(user=ada).delete()  # staff, in the admin
    assert signed_in_directly(Client())


def test_an_empty_entry_in_the_key_list_counts_as_not_set_in_development(settings):
    """An env reader that turns an empty CAPY_AUTH_ENCRYPTION_KEYS= into [""] (as the
    README's .env.example line can) should get the development stand-in, as the
    comma-separated string form already does."""
    settings.DEBUG = True
    settings.CAPY_AUTH_ENCRYPTION_KEYS = [""]
    assert [w.id for w in check_encryption_keys(None)] == ["capy_auth.W005"]


def test_a_key_list_with_spaces_after_the_commas_works(settings):
    one, two = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    settings.CAPY_AUTH_ENCRYPTION_KEYS = [one, f" {two}"]
    stored = crypto.encrypt("x")
    settings.CAPY_AUTH_ENCRYPTION_KEYS = [two, one]
    assert crypto.decrypt(stored) == "x"


def test_a_malformed_second_key_is_named(settings):
    settings.CAPY_AUTH_ENCRYPTION_KEYS = [Fernet.generate_key().decode(), "nope"]
    assert "key 2 of" in check_encryption_keys(None)[0].msg


def test_development_secrets_dont_survive_a_new_secret_key(settings):
    settings.DEBUG = True
    settings.CAPY_AUTH_ENCRYPTION_KEYS = []
    stored = crypto.encrypt("x")
    settings.SECRET_KEY = "another-secret-key-" * 3
    with pytest.raises(crypto.SecretUnreadable):
        crypto.decrypt(stored)


def test_debug_on_with_a_real_key_doesnt_warn(settings):
    settings.DEBUG = True
    assert check_encryption_keys(None) == []


# --- Other features ----------------------------------------------------------------------


@pytest.mark.django_db
def test_a_password_reset_doesnt_skip_the_code(with_app):
    client = Client()
    client.post(RESET, {"email": "ada@example.com"})
    link = reset_link(mail.outbox[-1])
    form_url = client.get(link).url
    new_password = NEW_PASSWORD
    client.post(form_url, {"password1": new_password, "password2": new_password})
    assert not signed_in(client)
    other = Client()
    assert log_in(other, password=new_password).url == AUTHENTICATE


@pytest.mark.django_db
def test_a_ban_during_the_code_step_stops_the_sign_in(with_app, ada):
    secret, _ = with_app
    client = at_code_step()
    suspend_accounts(BannedEmail.objects.create(email="ada@example.com"))
    client.post(AUTHENTICATE, {"code": totp.code(secret)})
    assert not signed_in(client)


@pytest.mark.django_db
def test_lifting_a_ban_keeps_the_app_and_still_asks_for_a_code(with_app, ada):
    ban = BannedEmail.objects.create(email="ada@example.com")
    suspend_accounts(ban)
    lift_bans(BannedEmail.objects.filter(pk=ban.pk))
    assert Authenticator.objects.filter(user=ada, type="totp").exists()
    user = get_user_model().objects.get(pk=ada.pk)
    user.set_password(PASSWORD)
    user.save()
    assert log_in(Client()).url == AUTHENTICATE


@pytest.mark.django_db
def test_the_pending_code_step_isnt_a_sign_in_for_other_pages(with_app):
    client = at_code_step()
    assert client.get(reverse("mfa_index")).status_code == 302
    assert client.get(reverse("usersessions_list")).status_code == 302
    assert client.get(reverse("account_change_password")).status_code == 302


@pytest.mark.django_db
def test_with_the_key_lost_the_recovery_codes_page_says_what_to_do(settings, with_app, ada):
    client = Client()
    client.force_login(ada)
    client.post(REAUTHENTICATE, {"password": PASSWORD})
    settings.CAPY_AUTH_ENCRYPTION_KEYS = [Fernet.generate_key().decode()]
    check_page(client.get(RECOVERY_CODES), status=503)


@pytest.mark.django_db
def test_the_status_line_in_production_without_a_key_doesnt_claim_a_stand_in(settings):
    """With DEBUG off there is no stand-in key (encrypt raises KeyProblem), so the
    status line shouldn't say one is in use."""
    from capy_auth.config.admin import AuthSettingsAdmin
    from capy_auth.config.models import AuthSettings

    settings.DEBUG = False
    settings.CAPY_AUTH_ENCRYPTION_KEYS = []
    line = str(AuthSettingsAdmin(AuthSettings, None).mfa_encryption(None))
    assert "development-only key is in use" not in line


@pytest.mark.django_db
def test_the_mfa_pages_need_a_sign_in(client):
    for name in ("mfa_index", "mfa_activate_totp", "mfa_view_recovery_codes"):
        assert client.get(reverse(name)).url.startswith(LOGIN)
