"""allauth's sign-in API ("headless", #36), which capy-auth's URLs include when a
project installs it: capy-auth's rules apply there too (signup closed, the ban list),
an app gets a session token, and that token never opens the admin."""

import importlib

import pytest
from django.apps import apps as django_apps
from django.contrib.auth import get_user_model
from django.core import mail
from django.test import Client
from django.urls import reverse

from capy_auth.bans.models import BannedEmail
from capy_auth.config.selectors import get_auth_settings
from capy_auth.social.models import SocialProvider
from tests import totp
from tests.accounts import PASSWORD
from tests.staff import make_staff, with_app
from tests.test_mfa import confirmed, set_up_app
from tests.test_passkeys_edges import break_cache

API = "/accounts/_allauth"
CONFIG = f"{API}/browser/v1/config"
APP_LOGIN = f"{API}/app/v1/auth/login"
APP_SIGNUP = f"{API}/app/v1/auth/signup"
APP_SESSION = f"{API}/app/v1/auth/session"


def post(client, path, data):
    return client.post(path, data, content_type="application/json")


@pytest.mark.django_db
def test_the_config_says_whether_signup_is_open(client):
    assert client.get(CONFIG).json()["data"]["account"]["is_open_for_signup"] is True
    record = get_auth_settings()
    record.signup_open = False
    record.save()
    assert client.get(CONFIG).json()["data"]["account"]["is_open_for_signup"] is False


@pytest.mark.django_db
def test_an_app_signs_in_and_gets_a_session_token(client, ada):
    response = post(client, APP_LOGIN, {"email": "ada@example.com", "password": PASSWORD})
    assert response.status_code == 200
    token = response.json()["meta"]["session_token"]
    session = client.get(APP_SESSION, HTTP_X_SESSION_TOKEN=token)
    assert session.json()["data"]["user"]["email"] == "ada@example.com"


@pytest.mark.django_db
def test_a_wrong_password_is_refused(client, ada):
    response = post(client, APP_LOGIN, {"email": "ada@example.com", "password": "nope-" + PASSWORD})
    assert response.status_code == 400


@pytest.mark.django_db
def test_a_banned_address_cant_sign_up_through_the_api(client):
    BannedEmail.objects.create(email="mallory@example.com")
    mail.outbox.clear()
    response = post(client, APP_SIGNUP, {"email": "mallory@example.com", "password": PASSWORD})
    assert response.status_code == 401  # as for any new address: "confirm your email"
    flows = response.json()["data"]["flows"]
    assert [flow["id"] for flow in flows if flow.get("is_pending")] == ["verify_email"]
    assert not get_user_model().objects.filter(email="mallory@example.com").exists()
    assert len(mail.outbox) == 1  # only the ban notice, as at signup on the site


def test_without_allauths_api_capy_auth_offers_none(monkeypatch):
    import capy_auth.urls

    installed = django_apps.is_installed
    monkeypatch.setattr(
        django_apps, "is_installed", lambda name: name != "allauth.headless" and installed(name)
    )
    try:
        urls = importlib.reload(capy_auth.urls)
        assert not any("_allauth" in str(p.pattern) for p in urls.urlpatterns)
    finally:
        monkeypatch.undo()
        importlib.reload(capy_auth.urls)


BROWSER_LOGIN = f"{API}/browser/v1/auth/login"
BROWSER_SESSION = f"{API}/browser/v1/auth/session"


@pytest.mark.django_db
def test_staff_without_two_step_get_the_same_redirect_on_the_browser_api(ada):
    """The browser API shares the site's cookies, so the staff rule applies."""
    make_staff(ada)
    client = Client(enforce_csrf_checks=False)
    assert (
        post(client, BROWSER_LOGIN, {"email": ada.email, "password": PASSWORD}).status_code == 200
    )
    response = client.get(BROWSER_SESSION)
    assert response.status_code == 302 and response.url == reverse("mfa_index")


@pytest.mark.django_db
def test_staff_who_used_two_step_on_the_browser_api_go_on(ada):
    make_staff(ada)
    secret = with_app(ada)
    client = Client()
    post(client, BROWSER_LOGIN, {"email": ada.email, "password": PASSWORD})
    post(client, f"{API}/browser/v1/auth/2fa/authenticate", {"code": totp.code(secret)})
    assert client.get(BROWSER_SESSION).status_code == 200
    assert client.get("/admin/").status_code == 200


@pytest.mark.django_db
def test_an_app_token_used_as_the_sites_cookie_meets_the_staff_rule(ada, settings):
    make_staff(ada, superuser=True)
    token = post(Client(), APP_LOGIN, {"email": ada.email, "password": PASSWORD}).json()
    client = Client()
    client.cookies[settings.SESSION_COOKIE_NAME] = token["meta"]["session_token"]
    response = client.get("/admin/")
    assert response.status_code == 302 and response.url == reverse("mfa_index")


@pytest.mark.django_db(transaction=True)  # allauth tells of it once the save commits
def test_adding_two_step_sign_in_ends_the_accounts_other_sessions(ada):
    app = post(Client(), APP_LOGIN, {"email": ada.email, "password": PASSWORD}).json()
    token = app["meta"]["session_token"]
    browser = confirmed(Client())
    set_up_app(browser)
    assert Client().get(APP_SESSION, HTTP_X_SESSION_TOKEN=token).status_code == 410
    assert browser.get(reverse("capy_auth_account")).status_code == 200  # this one stays


@pytest.mark.django_db
def test_with_the_cache_down_the_api_gets_the_503_answer(monkeypatch, ada):
    client = Client(raise_request_exception=False)
    break_cache(monkeypatch)
    response = post(client, APP_LOGIN, {"email": ada.email, "password": PASSWORD})
    assert response.status_code == 503


@pytest.mark.django_db
def test_a_switched_off_provider_is_refused_at_the_apis_address(client):
    SocialProvider.objects.filter(provider_id="github").update(enabled=False)
    response = client.post(
        f"{API}/browser/v1/auth/provider/redirect",
        {"provider": "github", "process": "login", "callback_url": "/"},
    )
    assert response.status_code == 404


@pytest.mark.django_db
def test_an_authenticator_added_outside_a_page_signs_nobody_out(ada):
    """allauth's signal without a request (a script): nothing to compare against."""
    from capy_auth.mfa.services import end_other_sessions

    end_other_sessions(sender=None, request=None, user=ada)
