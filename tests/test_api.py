"""allauth's sign-in API ("headless", #36), which capy-auth's URLs include when a
project installs it: capy-auth's rules apply there too (signup closed, the ban list),
an app gets a session token, and that token never opens the admin."""

import importlib

import pytest
from django.apps import apps as django_apps
from django.contrib.auth import get_user_model
from django.core import mail

from capy_auth.bans.models import BannedEmail
from capy_auth.config.selectors import get_auth_settings
from tests.accounts import PASSWORD
from tests.staff import make_staff

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
    post(client, APP_SIGNUP, {"email": "mallory@example.com", "password": PASSWORD})
    assert not get_user_model().objects.filter(email="mallory@example.com").exists()
    assert len(mail.outbox) == 1  # only the ban notice, as at signup on the site


@pytest.mark.django_db
def test_a_staff_api_session_never_opens_the_admin(client, ada):
    """The staff two-step rule works on pages; an app's session token isn't a page
    session, so it can't reach the admin (README: staff set it up on the website)."""
    make_staff(ada, superuser=True)
    token = post(client, APP_LOGIN, {"email": "ada@example.com", "password": PASSWORD}).json()
    response = client.get("/admin/", HTTP_X_SESSION_TOKEN=token["meta"]["session_token"])
    assert response.status_code == 302 and "/login/" in response.url


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
