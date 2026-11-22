"""Edge cases and security checks for signup, codes, login and reset: email case and
spaces, code limits, rate limits behind a proxy, timing, redirects and reset tokens."""

import re
import time
from datetime import datetime, timedelta

import pytest
from allauth.account.forms import default_token_generator
from allauth.account.internal.flows import code_verification
from allauth.account.models import EmailAddress
from django.contrib.auth import get_user_model
from django.core import mail
from django.core.cache import cache
from django.test import Client, RequestFactory

from capy_auth.account import adapter as capy_adapter
from tests.accounts import (
    ACCOUNT_PAGE,
    LOGIN,
    NEW_PASSWORD,
    PASSWORD,
    RESET,
    code_from,
    log_in,
    reset_link,
    sign_up,
    users_with_email,
)
from tests.helpers import check_page

WRONG_CODE = "AAAA-AAAA"


def reset_mails():
    return [message for message in mail.outbox if "/password/reset/key/" in message.body]


def make_user(email, verified=True, active=True):
    user = get_user_model().objects.create_user(
        username=email.split("@")[0], email=email, password=PASSWORD, is_active=active
    )
    EmailAddress.objects.create(user=user, email=user.email, primary=True, verified=verified)
    return user


def set_new_password(client, link):
    form_page = client.get(link, follow=True)
    client.post(
        form_page.redirect_chain[-1][0], {"password1": NEW_PASSWORD, "password2": NEW_PASSWORD}
    )
    return form_page


# --- Email case and spaces ---------------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize("typed", ["Eve@Example.COM", "  eve@example.com  ", "EVE@EXAMPLE.COM"])
def test_signup_keeps_the_email_lowercase_and_a_variant_makes_no_second_user(client, typed):
    assert sign_up(client, email=typed).status_code == 302
    assert EmailAddress.objects.get().email == "eve@example.com"
    assert get_user_model().objects.get().email == "eve@example.com"
    cache.clear()  # past allauth's "one code email per address every 3 minutes"
    assert sign_up(Client(), email="eve@example.com").status_code == 302  # not a 500
    assert users_with_email("eve@example.com").count() == 1


@pytest.mark.django_db
@pytest.mark.parametrize("typed", ["ADA@EXAMPLE.COM", "  ada@example.com ", "aDa@eXample.com"])
def test_login_accepts_case_and_spaces(client, ada, typed):
    assert log_in(client, email=typed).url == ACCOUNT_PAGE


@pytest.mark.django_db
@pytest.mark.parametrize("typed", ["ADA@EXAMPLE.COM", " ada@example.com "])
def test_reset_accepts_case_and_spaces(client, ada, typed):
    assert client.post(RESET, {"email": typed}).status_code == 302
    assert len(reset_mails()) == 1


@pytest.mark.django_db
def test_signup_with_the_email_of_a_user_who_has_no_email_record_makes_no_duplicate(client):
    # e.g. a superuser from createsuperuser: User.email set, no allauth EmailAddress.
    get_user_model().objects.create_user(
        username="root", email="root@example.com", password=PASSWORD
    )
    assert sign_up(client, email="Root@Example.com").status_code == 302
    assert users_with_email("root@example.com").count() == 1


@pytest.mark.django_db
def test_signup_while_logged_in_creates_no_one(client, ada):
    client.force_login(ada)
    assert sign_up(client).status_code == 302
    assert not users_with_email("eve@example.com").exists()


# --- Codes -------------------------------------------------------------------------------


@pytest.mark.django_db
def test_the_code_field_has_its_hint_and_no_autocorrect(client):
    page = check_page(client.get(sign_up(client).url))
    code_input = re.search(r'<input[^>]*name="code"[^>]*>', page).group(0)
    assert 'autocorrect="off"' in code_input
    assert 'spellcheck="false"' in page
    assert 'aria-describedby="id_code_hint"' in page
    assert "8 letters and numbers" in page


@pytest.mark.django_db
def test_the_code_page_offers_a_new_code_but_not_a_different_email(client):
    page = check_page(client.get(sign_up(client).url))
    assert 'form="resend"' in page
    # Offering "use a different email" would show only on a new signup's page, not a
    # taken email's, giving away which emails have accounts.
    assert 'value="change"' not in page


@pytest.mark.django_db
def test_three_wrong_codes_end_the_attempt_with_a_clear_message(client):
    code_url = sign_up(client).url
    code = code_from(mail.outbox[0])
    for _ in range(2):
        client.post(code_url, {"code": WRONG_CODE})
    response = client.post(code_url, {"code": WRONG_CODE}, follow=True)
    assert "If you were entering a code, it can’t be used any more" in check_page(response)
    client.post(code_url, {"code": code})
    assert not EmailAddress.objects.get(email="eve@example.com").verified


@pytest.mark.django_db
@pytest.mark.parametrize(("minutes", "works"), [(14, True), (15.1, False)])
def test_a_code_works_for_15_minutes(client, monkeypatch, minutes, works):
    code_url = sign_up(client).url
    later = time.time() + minutes * 60
    monkeypatch.setattr(code_verification.time, "time", lambda: later)
    client.post(code_url, {"code": code_from(mail.outbox[0])})
    assert EmailAddress.objects.get(email="eve@example.com").verified is works


@pytest.mark.django_db
def test_a_code_works_only_in_the_browser_that_signed_up(client):
    code_url = sign_up(client).url
    Client().post(code_url, {"code": code_from(mail.outbox[0])})
    assert not EmailAddress.objects.get(email="eve@example.com").verified


def without_per_page_values(page):
    """The page without what differs on every request (CSRF token, nonce) or per person."""
    page = re.sub(r'value="[^"]{20,}"', 'value=""', page)
    page = re.sub(r'nonce="[^"]+"', 'nonce=""', page)
    return re.sub(r"[\w.]+@example\.com", "", page)


@pytest.mark.django_db
def test_a_taken_emails_code_page_looks_the_same_and_accepts_no_code(ada):
    new_client, taken_client = Client(), Client()
    new = check_page(new_client.get(sign_up(new_client).url))
    taken_url = sign_up(taken_client, email="ada@example.com").url
    taken = check_page(taken_client.get(taken_url))
    assert without_per_page_values(new) == without_per_page_values(taken)
    # No code was sent for the taken address, so no code can finish a second signup.
    taken_client.post(taken_url, {"code": WRONG_CODE})
    assert users_with_email("ada@example.com").count() == 1
    assert taken_client.get(ACCOUNT_PAGE).status_code == 302


@pytest.mark.django_db
def test_signing_up_again_too_soon_gets_a_page_inside_the_layout(client):
    sign_up(client)
    page = check_page(sign_up(Client()), status=429)
    assert "Too many attempts" in page


# --- Security ----------------------------------------------------------------------------


@pytest.mark.django_db
def test_a_taken_email_takes_a_password_hash_like_a_new_account(client, ada, monkeypatch):
    hashed = []
    real = capy_adapter.make_password
    monkeypatch.setattr(
        capy_adapter, "make_password", lambda value: hashed.append(1) or real(value)
    )
    sign_up(client, email="ada@example.com")
    assert hashed == [1]


def client_ip(settings, forwarded_for, proxies):
    settings.ALLAUTH_TRUSTED_PROXY_COUNT = proxies
    request = RequestFactory().get("/", REMOTE_ADDR="10.0.0.2", HTTP_X_FORWARDED_FOR=forwarded_for)
    return capy_adapter.AccountAdapter(request).get_client_ip(request)


def test_behind_a_proxy_each_visitor_is_counted_by_their_own_address(settings):
    assert client_ip(settings, "203.0.113.5", proxies=1) == "203.0.113.5"
    assert client_ip(settings, "203.0.113.6", proxies=1) == "203.0.113.6"
    # A forged entry in front is ignored: the proxy adds the real address last.
    assert client_ip(settings, "1.2.3.4, 203.0.113.5", proxies=1) == "203.0.113.5"
    # Without the setting, everyone behind the proxy shares the proxy's address.
    assert client_ip(settings, "203.0.113.5", proxies=0) == "10.0.0.2"


@pytest.mark.django_db
def test_a_login_limit_for_one_visitor_doesnt_block_another(settings, ada):
    settings.ALLAUTH_TRUSTED_PROXY_COUNT = 1
    settings.ACCOUNT_RATE_LIMITS = {"login_failed": "2/m/ip"}
    attacker = Client(REMOTE_ADDR="10.0.0.2", HTTP_X_FORWARDED_FOR="203.0.113.66")
    for _ in range(3):
        log_in(attacker, password=NEW_PASSWORD)
    assert "Too many attempts" in log_in(attacker).content.decode()  # the limit fires
    visitor = Client(REMOTE_ADDR="10.0.0.2", HTTP_X_FORWARDED_FOR="203.0.113.7")
    assert log_in(visitor).url == ACCOUNT_PAGE


@pytest.mark.django_db
def test_logging_in_gives_a_new_session(client, ada):
    client.get(LOGIN)
    before = client.session.session_key
    log_in(client)
    assert client.session.session_key != before


@pytest.mark.django_db
@pytest.mark.parametrize("next_url", ["//evil.example/", "/\\evil.example/", "https:evil.example"])
def test_tricky_next_links_to_other_sites_are_ignored(client, ada, next_url):
    response = client.post(
        f"{LOGIN}?next={next_url}", {"login": "ada@example.com", "password": PASSWORD}
    )
    assert response.url == ACCOUNT_PAGE


@pytest.mark.django_db
def test_the_reset_token_is_taken_out_of_the_address(client, ada):
    client.post(RESET, {"email": "ada@example.com"})
    link = reset_link(mail.outbox[0])
    token = link.rstrip("/").rsplit("/", 1)[-1].split("-", 1)[1]
    form_page = client.get(link, follow=True)
    assert token not in form_page.redirect_chain[-1][0]  # can't leak in a Referer header


# --- Reset edge cases --------------------------------------------------------------------


@pytest.mark.django_db
def test_reset_for_an_inactive_user_sends_nothing_and_looks_the_same(client):
    make_user("ina@example.com", active=False)
    inactive = client.post(RESET, {"email": "ina@example.com"})
    unknown = Client().post(RESET, {"email": "nobody@example.com"})
    assert inactive.status_code == unknown.status_code == 302
    assert inactive.url == unknown.url
    assert reset_mails() == []


@pytest.mark.django_db
def test_a_completed_reset_confirms_the_address_the_link_went_to(client):
    """The link reached that inbox, as a code would have (allauth's reset by code
    confirms it too), so Bob can log in without another code."""
    bob = make_user("bob@example.com", verified=False)
    client.post(RESET, {"email": "bob@example.com"})
    set_new_password(client, reset_link(reset_mails()[0]))
    assert bob.emailaddress_set.get().verified
    assert log_in(Client(), email="bob@example.com", password=NEW_PASSWORD).url == ACCOUNT_PAGE


@pytest.mark.django_db
def test_a_reset_link_dies_when_the_email_changes(client, ada):
    client.post(RESET, {"email": "ada@example.com"})
    link = reset_link(mail.outbox[0])
    ada.email = "ada2@example.com"
    ada.save()
    assert 'name="password1"' not in Client().get(link, follow=True).content.decode()


@pytest.mark.django_db
def test_a_reset_link_still_works_at_59_minutes(client, ada, monkeypatch):
    client.post(RESET, {"email": "ada@example.com"})
    later = datetime.now() + timedelta(minutes=59)  # the token clock's own time
    monkeypatch.setattr(default_token_generator, "_now", lambda: later)
    page = client.get(reset_link(mail.outbox[0]), follow=True).content.decode()
    assert 'name="password1"' in page


@pytest.mark.django_db
def test_after_a_reset_the_old_password_fails_and_other_sessions_end(client, ada):
    laptop = Client()
    assert log_in(laptop).url == ACCOUNT_PAGE
    client.post(RESET, {"email": "ada@example.com"})
    set_new_password(client, reset_link(mail.outbox[0]))
    assert laptop.get(ACCOUNT_PAGE).status_code == 302
    assert log_in(Client(), password=PASSWORD).status_code == 200  # refused
    assert log_in(Client(), password=NEW_PASSWORD).url == ACCOUNT_PAGE


@pytest.mark.django_db
def test_using_one_reset_link_kills_the_other(client, ada):
    client.post(RESET, {"email": "ada@example.com"})
    client.post(RESET, {"email": "ada@example.com"})
    first, second = (reset_link(message) for message in reset_mails())
    set_new_password(client, first)
    assert 'name="password1"' not in Client().get(second, follow=True).content.decode()


@pytest.mark.django_db
def test_an_inactive_user_with_the_right_password_isnt_logged_in(client):
    make_user("ina@example.com", active=False)
    log_in(client, email="ina@example.com")
    assert client.get(ACCOUNT_PAGE).status_code == 302
