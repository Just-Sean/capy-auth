"""The passkey pages: capy-auth's words, the second step worded for the ways a person
has set up, and every page wired to allauth's scripts and capy-auth's (passkeys.js),
under the strict policy."""

import json
import re

import pytest
from django.contrib.staticfiles import finders
from django.test import Client

from tests import test_passkeys, totp
from tests.accounts import LOGIN, log_in
from tests.helpers import check_page
from tests.test_mfa import ACTIVATE, AUTHENTICATE, MFA_PAGE, REAUTHENTICATE, SECRET
from tests.test_passkeys import ADD, LIST, REAUTHENTICATE_WITH_PASSKEY, managing

phone = test_passkeys.phone  # the fixture, shared


# --- The pages ------------------------------------------------------------------------


@pytest.mark.django_db
def test_the_overview_offers_passkeys_and_counts_them(ada, phone):
    page = check_page(managing(ada).get(MFA_PAGE))
    assert "You’ve added 1 passkey or security key." in page
    assert "Manage passkeys and security keys" in page


@pytest.mark.django_db
def test_the_overview_without_any_offers_adding_one(client, ada):
    log_in(client)
    page = check_page(client.get(MFA_PAGE))
    assert f'href="{ADD}"' in page and "Add a passkey or security key" in page


@pytest.mark.django_db
def test_the_list_without_any_says_so_and_offers_adding_one(client, ada):
    log_in(client)
    page = check_page(client.get(LIST))
    assert "None added yet." in page
    assert f'href="{ADD}"' in page and f'href="{MFA_PAGE}"' in page


@pytest.mark.django_db
def test_the_second_step_asks_a_passkey_only_person_for_their_passkey(phone):
    client = Client()
    log_in(client)
    page = check_page(client.get(AUTHENTICATE))
    assert re.search(r"<title>\s*Use your passkey or security key", page)
    assert "authenticator app" not in page
    body = page.split("</head>", 1)[1]
    assert body.index('id="mfa_webauthn_authenticate"') < body.index('name="code"')
    assert "Sign in with a recovery code" in page and "Cancel and sign out" in page


@pytest.mark.django_db
def test_the_second_step_asks_for_the_app_code_first_when_there_is_an_app(ada, phone):
    client = managing(ada)
    secret = SECRET.search(client.get(ACTIVATE).content.decode()).group(0)
    client.post(ACTIVATE, {"code": totp.code(secret)})
    fresh = Client()
    log_in(fresh)
    page = check_page(fresh.get(AUTHENTICATE))
    assert "Enter your sign-in code" in page and "or use your passkey" in page
    body = page.split("</head>", 1)[1]
    assert body.index('name="code"') < body.index('id="mfa_webauthn_authenticate"')


@pytest.mark.django_db
def test_the_confirm_page_offers_the_passkey_in_capy_auths_words(ada, phone):
    client = Client()
    client.force_login(ada)
    page = check_page(client.get(REAUTHENTICATE))
    assert "Use a passkey or security key" in page
    assert "Use a security key" not in page


def onload_ids(page):
    """Every element id the passkey scripts on a page look up (allauth's onload JSON)."""
    blocks = re.findall(
        r'<script data-allauth-onload="[^"]+" type="application/json">(.*?)'
        r"</script>",
        page,
        re.S,
    )
    assert blocks
    return [value for block in blocks for value in json.loads(block)["ids"].values()]


@pytest.mark.django_db
def test_every_passkey_page_has_what_its_scripts_need(ada, phone):
    """The scripts find their buttons, fields and data by id; the buttons do nothing
    without JavaScript; capy-auth's script and status line are there."""
    managed = managing(ada)
    second_step = Client()
    log_in(second_step)
    pages = [
        check_page(Client().get(LOGIN)),
        check_page(managed.get(ADD)),
        check_page(managed.get(REAUTHENTICATE_WITH_PASSKEY)),
        check_page(second_step.get(AUTHENTICATE)),
    ]
    for page in pages:
        body = page.split("</head>", 1)[1]
        for element_id in onload_ids(page):
            assert f'id="{element_id}"' in body, element_id
        for form_id in re.findall(r'\bform="([^"]+)"', body):
            assert f'id="{form_id}"' in body, form_id
        assert 'id="capy_auth_passkey_status"' in body and "<noscript>" in body
        assert "capy_auth/js/passkeys.js" in page
        for button in re.findall(r"<button[^>]*>", body):
            if re.search(r'id="(passkey_login|mfa_webauthn_\w+)"', button):
                assert 'type="button"' in button, button
    assert finders.find("capy_auth/js/passkeys.js")
