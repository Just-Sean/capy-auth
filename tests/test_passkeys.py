"""Passkeys and security keys (allauth's WebAuthn), with a software passkey standing in
for a phone (tests/webauthn.py): adding one, signing in with it on its own ("Sign in
with a passkey"), as the second step after the password, confirming a change with it,
renaming and removing it; and the checks capy_auth.E009 and W006. The pages are in
test_passkey_pages.py; more ways to try to break them are in test_passkeys_edges.py."""

import re

import pytest
from allauth.mfa.models import Authenticator
from django.template.loader import render_to_string
from django.test import Client
from django.urls import reverse

from capy_auth.mfa import checks
from capy_auth.mfa.checks import check_passkey_forms, check_passkey_origin
from capy_auth.mfa.forms import AddPasskeyForm
from tests import totp
from tests.accounts import ACCOUNT_PAGE, LOGIN, PASSWORD, log_in
from tests.helpers import check_page
from tests.test_mfa import (
    ACTIVATE,
    AUTHENTICATE,
    DEACTIVATE,
    REAUTHENTICATE,
    SECRET,
    confirmed,
)
from tests.webauthn import SoftPasskey, page_data

ADD = reverse("mfa_add_webauthn")
LIST = reverse("mfa_list_webauthn")
PASSKEY_LOGIN = reverse("mfa_login_webauthn")
REAUTHENTICATE_WITH_PASSKEY = reverse("mfa_reauthenticate_webauthn")
AJAX = {"HTTP_X_REQUESTED_WITH": "XMLHttpRequest"}


def add(client, passkey=True, name="My phone"):
    authenticator = SoftPasskey(passkey=passkey)
    page = check_page(client.get(ADD))
    credential = authenticator.register(page_data(page)["creation_options"])
    data = {"name": name, "credential": credential}
    if passkey:
        data["passwordless"] = "on"
    response = client.post(ADD, data)
    assert response.status_code == 302, response.content.decode()[-2000:]
    return authenticator


def passkey_login(client, authenticator, **data):
    options = client.get(PASSKEY_LOGIN, **AJAX).json()["request_options"]
    return client.post(PASSKEY_LOGIN, {"credential": authenticator.sign(options), **data})


@pytest.fixture
def phone(ada):
    return add(confirmed(Client()))


def signed_in(client):
    return client.get(ACCOUNT_PAGE).status_code == 200


def managing(user):
    """Signed in and confirmed by password (signing in now needs the passkey)."""
    client = Client()
    client.force_login(user)
    client.post(REAUTHENTICATE, {"password": PASSWORD})
    return client


# --- Adding one ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_adding_a_passkey_asks_for_the_password_first(client, ada):
    log_in(client)
    assert client.get(ADD).url.startswith(REAUTHENTICATE)


@pytest.mark.django_db
def test_the_add_page_ticks_sign_in_without_a_password_and_suggests_a_name(ada):
    page = check_page(confirmed(Client()).get(ADD))
    checkbox = re.search(r'<input type="checkbox" name="passwordless"[^>]*>', page).group(0)
    assert "checked" in checkbox
    assert "Let it sign me in without my password" in page
    assert "Passwordless" not in page  # allauth's word
    assert 'value="Passkey 1"' in page and "My phone" in page  # the hint
    assert 'maxlength="100"' in page


@pytest.mark.django_db
def test_a_passkey_is_added_and_listed(ada, phone):
    stored = Authenticator.objects.get(user=ada, type="webauthn")
    assert stored.wrap().is_passwordless is True
    page = check_page(managing(ada).get(LIST))
    assert "My phone" in page
    assert "Rename My phone" in page and "Remove My phone" in page
    assert "a second step" not in page  # nothing promises the password is still needed


@pytest.mark.django_db
def test_adding_one_also_makes_recovery_codes(ada, phone):
    assert Authenticator.objects.filter(user=ada, type="recovery_codes").exists()


@pytest.mark.django_db
def test_a_new_key_without_a_name_gets_a_numbered_one(ada, phone):
    add(managing(ada), name="")
    names = {a.wrap().name for a in Authenticator.objects.filter(user=ada, type="webauthn")}
    assert names == {"My phone", "Passkey 2"}


# --- Signing in -----------------------------------------------------------------------


@pytest.mark.django_db
def test_sign_in_with_a_passkey_on_its_own(phone):
    client = Client()
    page = check_page(client.get(LOGIN))
    assert '<form id="mfa_login"' in page.split("</head>", 1)[1]  # in the content
    response = passkey_login(client, phone)
    assert response.status_code == 302
    assert signed_in(client)


@pytest.mark.django_db
def test_a_passkey_answer_for_another_challenge_doesnt_sign_in(phone):
    stale = Client().get(PASSKEY_LOGIN, **AJAX).json()["request_options"]
    client = Client()
    client.get(PASSKEY_LOGIN, **AJAX)
    client.post(PASSKEY_LOGIN, {"credential": phone.sign(stale)})
    assert not signed_in(client)


@pytest.mark.django_db
def test_an_unknown_passkey_doesnt_sign_in(phone):
    stranger = SoftPasskey()
    stranger.user_handle = phone.user_handle
    client = Client()
    passkey_login(client, stranger)
    assert not signed_in(client)


@pytest.mark.django_db
def test_a_forged_signature_doesnt_sign_in(phone):
    forger = SoftPasskey()  # the right key id and account, but not the key itself
    forger.credential_id, forger.user_handle = phone.credential_id, phone.user_handle
    client = Client()
    passkey_login(client, forger)
    assert not signed_in(client)


@pytest.mark.django_db
@pytest.mark.parametrize("origin", ["https://evil.example", "http://testserver"])
def test_an_answer_from_another_site_doesnt_sign_in(phone, origin):
    phone.origin = origin
    client = Client()
    passkey_login(client, phone)
    assert not signed_in(client)


@pytest.mark.django_db
def test_after_the_password_a_passkey_is_the_second_step(phone):
    client = Client()
    assert log_in(client).url == AUTHENTICATE
    options = page_data(check_page(client.get(AUTHENTICATE)))["request_options"]
    client.post(AUTHENTICATE, {"credential": phone.sign(options)})
    assert signed_in(client)


@pytest.mark.django_db
def test_an_older_security_key_works_as_the_second_step(ada):
    key = add(confirmed(Client()), passkey=False, name="Blue key")
    client = Client()
    log_in(client)
    options = page_data(check_page(client.get(AUTHENTICATE)))["request_options"]
    client.post(AUTHENTICATE, {"credential": key.sign(options)})
    assert signed_in(client)


@pytest.mark.django_db
def test_any_key_the_device_saved_as_a_passkey_signs_in_on_its_own(ada):
    """allauth doesn't store the box: a key added without it that the device saved as a
    passkey anyway (phones and computers often do) still signs in on its own, as the
    add page says (Sean's decision on #28)."""
    key = add(confirmed(Client()), passkey=False, name="Blue key")
    key.passkey = True
    client = Client()
    passkey_login(client, key)
    assert signed_in(client)


@pytest.mark.django_db
def test_a_change_can_be_confirmed_with_the_passkey(ada, phone):
    client = Client()
    client.force_login(ada)
    page = check_page(client.get(REAUTHENTICATE_WITH_PASSKEY))
    assert "Use a passkey or security key" in page
    options = page_data(page)["request_options"]
    client.post(REAUTHENTICATE_WITH_PASSKEY, {"credential": phone.sign(options)})
    assert client.get(ADD).status_code == 200  # confirmed: no password asked


# --- Renaming and removing --------------------------------------------------------------


@pytest.mark.django_db
def test_renaming_and_removing_a_passkey(ada, phone):
    client = managing(ada)
    stored = Authenticator.objects.get(user=ada, type="webauthn")
    edit = reverse("mfa_edit_webauthn", kwargs={"pk": stored.pk})
    assert f'action="{edit}"' in check_page(client.get(edit))
    client.post(edit, {"name": "Work phone"})
    assert "Work phone" in check_page(client.get(LIST))
    remove = reverse("mfa_remove_webauthn", kwargs={"pk": stored.pk})
    page = check_page(client.get(remove))
    assert "Remove Work phone?" in page and "Keep it" in page
    client.post(remove)
    assert not Authenticator.objects.filter(type="webauthn").exists()


@pytest.mark.django_db
def test_removing_the_last_one_turns_two_step_sign_in_off(ada, phone):
    stored = Authenticator.objects.get(user=ada, type="webauthn")
    managing(ada).post(reverse("mfa_remove_webauthn", kwargs={"pk": stored.pk}))
    assert not Authenticator.objects.filter(user=ada).exists()  # the codes went too
    client = Client()
    log_in(client)
    assert signed_in(client)  # the password alone, as the remove page warns


@pytest.mark.django_db
def test_turning_off_the_app_keeps_the_codes_while_a_passkey_remains(ada, phone):
    client = managing(ada)
    secret = SECRET.search(client.get(ACTIVATE).content.decode()).group(0)
    client.post(ACTIVATE, {"code": totp.code(secret)})
    client.post(DEACTIVATE)
    assert not Authenticator.objects.filter(user=ada, type="totp").exists()
    assert Authenticator.objects.filter(user=ada, type="recovery_codes").exists()


def test_the_messages_say_when_two_step_sign_in_may_be_off():
    for name in ("webauthn_removed", "totp_deactivated"):
        message = render_to_string(f"mfa/messages/{name}.txt")
        assert "two-step sign-in is now off" in message


# --- The checks ---------------------------------------------------------------------------


def test_the_insecure_origin_switch_is_refused_in_production(settings):
    assert check_passkey_origin(None) == []
    settings.MFA_WEBAUTHN_ALLOW_INSECURE_ORIGIN = True
    assert [e.id for e in check_passkey_origin(None)] == ["capy_auth.E009"]
    assert "from .core import DEBUG" in check_passkey_origin(None)[0].hint
    settings.DEBUG = True  # development over http needs it
    assert check_passkey_origin(None) == []


def test_without_capy_auths_passkey_forms_a_warning_says_how(settings):
    assert check_passkey_forms(None) == []
    del settings.MFA_FORMS
    [warning] = check_passkey_forms(None)
    assert warning.id == "capy_auth.W006" and "capy_auth.mfa.forms" in warning.hint


def test_without_allauths_mfa_app_there_is_no_passkey_forms_warning(monkeypatch):
    monkeypatch.setattr(checks.apps, "is_installed", lambda name: False)
    assert check_passkey_forms(None) == []


@pytest.mark.django_db
def test_with_passkey_sign_in_off_the_add_form_has_no_box(monkeypatch, ada):
    """allauth adds the box only when passkey sign-in is on (when it loads)."""
    monkeypatch.delitem(AddPasskeyForm.base_fields, "passwordless")
    assert "passwordless" not in AddPasskeyForm(user=ada).fields
