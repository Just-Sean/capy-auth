"""Passkeys and security keys (allauth's WebAuthn), with a software passkey standing in
for a phone (tests/webauthn.py): adding one, signing in with it on its own ("Sign in
with a passkey"), as the second step after the password, confirming a change with it,
renaming and removing it; the pages in capy-auth's words under the strict policy; and
the check capy_auth.E009."""

import pytest
from allauth.mfa.models import Authenticator
from django.test import Client
from django.urls import reverse

from capy_auth.mfa.checks import check_passkey_origin
from tests import totp
from tests.accounts import ACCOUNT_PAGE, LOGIN, PASSWORD, log_in
from tests.helpers import check_page
from tests.test_mfa import ACTIVATE, SECRET
from tests.webauthn import SoftPasskey, page_data

ADD = reverse("mfa_add_webauthn")
LIST = reverse("mfa_list_webauthn")
PASSKEY_LOGIN = reverse("mfa_login_webauthn")
AUTHENTICATE = reverse("mfa_authenticate")
REAUTHENTICATE = reverse("account_reauthenticate")
MFA_PAGE = reverse("mfa_index")
AJAX = {"HTTP_X_REQUESTED_WITH": "XMLHttpRequest"}


def confirmed(client):
    log_in(client)
    client.post(REAUTHENTICATE, {"password": PASSWORD})
    return client


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


@pytest.fixture
def phone(ada):
    return add(confirmed(Client()))


def signed_in(client):
    return client.get(ACCOUNT_PAGE).status_code == 200


# --- Adding one ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_adding_a_passkey_asks_for_the_password_first(client, ada):
    log_in(client)
    assert client.get(ADD).url.startswith(REAUTHENTICATE)


@pytest.mark.django_db
def test_a_passkey_is_added_and_listed(ada, phone):
    stored = Authenticator.objects.get(user=ada, type="webauthn")
    assert stored.wrap().is_passwordless is True
    client = Client()
    client.force_login(ada)
    page = check_page(client.get(LIST))
    assert "My phone" in page
    assert "Passkey: signs you in on its own" in page
    assert "Rename My phone" in page and "Remove My phone" in page


@pytest.mark.django_db
def test_adding_one_also_makes_recovery_codes(ada, phone):
    assert Authenticator.objects.filter(user=ada, type="recovery_codes").exists()


@pytest.mark.django_db
def test_a_security_key_is_a_second_step(ada):
    add(confirmed(Client()), passkey=False, name="Blue key")
    client = Client()
    client.force_login(ada)
    assert "Security key: a second step" in check_page(client.get(LIST))


# --- Signing in -----------------------------------------------------------------------


@pytest.mark.django_db
def test_sign_in_with_a_passkey_on_its_own(phone):
    client = Client()
    page = check_page(client.get(LOGIN))
    assert 'id="passkey_login"' in page
    assert '<form id="mfa_login"' in page.split("</head>", 1)[1]  # in the content
    options = client.get(PASSKEY_LOGIN, **AJAX).json()["request_options"]
    response = client.post(PASSKEY_LOGIN, {"credential": phone.sign(options)})
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
    client = Client()
    options = client.get(PASSKEY_LOGIN, **AJAX).json()["request_options"]
    stranger = SoftPasskey()
    stranger.user_handle = phone.user_handle
    client.post(PASSKEY_LOGIN, {"credential": stranger.sign(options)})
    assert not signed_in(client)


@pytest.mark.django_db
def test_after_the_password_a_passkey_is_the_second_step(phone):
    client = Client()
    assert log_in(client).url == AUTHENTICATE
    page = check_page(client.get(AUTHENTICATE))
    options = page_data(page)["request_options"]
    client.post(AUTHENTICATE, {"credential": phone.sign(options)})
    assert signed_in(client)


@pytest.mark.django_db
def test_a_change_can_be_confirmed_with_the_passkey(ada, phone):
    client = Client()
    client.force_login(ada)
    page = check_page(client.get(reverse("mfa_reauthenticate_webauthn")))
    assert "Use a passkey or security key" in page
    options = page_data(page)["request_options"]
    client.post(reverse("mfa_reauthenticate_webauthn"), {"credential": phone.sign(options)})
    assert client.get(ADD).status_code == 200  # confirmed: no password asked


# --- Renaming and removing --------------------------------------------------------------


@pytest.mark.django_db
def test_renaming_and_removing_a_passkey(ada, phone):
    client = Client()
    client.force_login(ada)  # signing in now needs the passkey: confirm by password
    client.post(REAUTHENTICATE, {"password": PASSWORD})
    stored = Authenticator.objects.get(user=ada, type="webauthn")
    edit = reverse("mfa_edit_webauthn", kwargs={"pk": stored.pk})
    check_page(client.get(edit))
    client.post(edit, {"name": "Work phone"})
    assert "Work phone" in check_page(client.get(LIST))
    remove = reverse("mfa_remove_webauthn", kwargs={"pk": stored.pk})
    page = check_page(client.get(remove))
    assert "Remove Work phone?" in page and "Keep it" in page
    client.post(remove)
    assert not Authenticator.objects.filter(type="webauthn").exists()


# --- The pages ------------------------------------------------------------------------


@pytest.mark.django_db
def test_the_overview_offers_passkeys(client, ada):
    log_in(client)
    page = check_page(client.get(MFA_PAGE))
    assert "Passkeys and security keys" in page
    assert f'href="{ADD}"' in page and "Add a passkey" in page


@pytest.mark.django_db
def test_the_list_without_any_says_so_and_offers_adding_one(client, ada):
    log_in(client)
    page = check_page(client.get(LIST))
    assert "None added yet." in page
    assert f'href="{ADD}"' in page and f'href="{MFA_PAGE}"' in page


@pytest.mark.django_db
def test_turning_off_the_app_keeps_the_codes_while_a_passkey_remains(ada, phone):
    client = Client()
    client.force_login(ada)
    client.post(REAUTHENTICATE, {"password": PASSWORD})
    page = client.get(ACTIVATE).content.decode()
    secret = SECRET.search(page).group(0)
    client.post(ACTIVATE, {"code": totp.code(secret)})
    client.post(reverse("mfa_deactivate_totp"))
    assert not Authenticator.objects.filter(user=ada, type="totp").exists()
    assert Authenticator.objects.filter(user=ada, type="recovery_codes").exists()


# --- The check ----------------------------------------------------------------------------


def test_the_insecure_origin_switch_is_refused_in_production(settings):
    assert check_passkey_origin(None) == []
    settings.MFA_WEBAUTHN_ALLOW_INSECURE_ORIGIN = True
    assert [e.id for e in check_passkey_origin(None)] == ["capy_auth.E009"]
    settings.DEBUG = True  # development over http needs it
    assert check_passkey_origin(None) == []
