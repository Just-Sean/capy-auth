"""Social sign-in's framework (capy_auth/social/, 14a of #33): providers set up in the
settings (tests/settings.py: GitHub, switched on by CAPY_AUTH_SOCIAL_PROVIDERS_ON, and a
company's OpenID Connect server, off), switched on and off on the dashboard, database-
stored apps ignored, the admin page, and the checks capy_auth.E013 and E014."""

import importlib
import secrets

import pytest
from allauth.socialaccount.adapter import _build_apps_from_settings, get_adapter
from allauth.socialaccount.models import SocialApp
from allauth.socialaccount.providers.dummy.provider import DummyProvider
from django.apps import apps as django_apps
from django.contrib import admin
from django.http import Http404
from django.urls import reverse

from capy_auth.config.checks import check_security_settings
from capy_auth.social import adapter as adapter_module
from capy_auth.social import admin as admin_module
from capy_auth.social import checks
from capy_auth.social.admin import NOT_SET_UP, SocialProviderAdmin
from capy_auth.social.models import SocialProvider
from capy_auth.social.services import add_new_providers
from tests.accounts import PASSWORD
from tests.staff import two_step_client

PROVIDERS_PAGE = reverse("admin:capy_auth_socialprovider_changelist")
GITHUB_LOGIN = reverse("github_login")


def offered():
    return {provider.sub_id for provider in get_adapter().list_providers(None)}


def switch(provider_id, on):
    SocialProvider.objects.filter(provider_id=provider_id).update(enabled=on)


# --- Which providers are offered ----------------------------------------------------------


@pytest.mark.django_db
def test_migrate_lists_each_set_up_provider_with_its_starting_state():
    states = dict(SocialProvider.objects.values_list("provider_id", "enabled"))
    assert states == {"github": True, "company-sso": False}


@pytest.mark.django_db
def test_only_switched_on_providers_are_offered():
    assert offered() == {"github"}
    switch("company-sso", True)
    switch("github", False)
    assert offered() == {"company-sso"}


@pytest.mark.django_db
def test_a_switched_off_provider_cant_be_used_even_at_its_address(client):
    assert client.get(GITHUB_LOGIN).status_code in (200, 302)  # on: allauth's flow
    switch("github", False)
    with pytest.raises(SocialApp.DoesNotExist):
        get_adapter().get_app(None, "github")
    assert client.get(GITHUB_LOGIN).status_code == 404


@pytest.mark.django_db
def test_migrate_again_keeps_the_dashboards_choice_and_rows_of_providers_gone(settings):
    switch("github", False)
    SocialProvider.objects.create(provider_id="gitlab", enabled=True)  # no longer set up
    settings.CAPY_AUTH_SOCIAL_PROVIDERS_ON = ["github", "company-sso"]
    add_new_providers()
    states = dict(SocialProvider.objects.values_list("provider_id", "enabled"))
    assert states == {"github": False, "company-sso": False, "gitlab": True}
    assert offered() == set()  # github switched off; gitlab has no credentials to offer


@pytest.mark.django_db
def test_a_provider_stored_in_the_database_is_never_used():
    """allauth's SocialApp keeps the secret in the database: capy-auth ignores it."""
    stored = SocialApp.objects.create(
        provider="github", client_id="from-db", secret=secrets.token_urlsafe()
    )
    assert [app.client_id for app in get_adapter().list_apps(None)] == ["test-github"]
    stored.delete()


@pytest.mark.django_db
def test_the_providers_are_read_without_querying_allauths_table(django_assert_num_queries):
    with django_assert_num_queries(0):
        apps = _build_apps_from_settings()  # allauth's own code capy-auth relies on
    assert {app.provider_id or app.provider for found in apps.values() for app in found} == {
        "github",
        "company-sso",
    }


@pytest.mark.django_db
def test_the_pretend_provider_is_hidden_and_refused_when_switched_off(monkeypatch, rf):
    """allauth's pretend provider has no credentials, so list_apps can't refuse it."""
    pretend = DummyProvider(rf.get("/"), app=None)
    base = adapter_module.DefaultSocialAccountAdapter
    monkeypatch.setattr(base, "list_providers", lambda self, request: [pretend])
    monkeypatch.setattr(base, "get_provider", lambda self, *args, **kwargs: pretend)
    assert offered() == set()
    with pytest.raises(Http404):
        get_adapter().get_provider(None, "dummy")
    SocialProvider.objects.create(provider_id="dummy", enabled=True)
    assert offered() == {"dummy"}
    assert get_adapter().get_provider(None, "dummy") is pretend


# --- The dashboard ------------------------------------------------------------------------


@pytest.fixture
def superuser_client(django_user_model):
    superuser = django_user_model.objects.create_superuser(
        username="root", email="root@example.com", password=PASSWORD
    )
    return two_step_client(superuser)


@pytest.mark.django_db
def test_the_dashboard_lists_providers_and_where_to_register_them(superuser_client):
    SocialProvider.objects.create(provider_id="gitlab")
    response = superuser_client.get(PROVIDERS_PAGE)
    assert response.status_code == 200
    page = response.content.decode()
    assert "GitHub" in page and "OpenID Connect" in page
    assert reverse("github_callback") in page
    assert reverse("openid_connect_callback", kwargs={"provider_id": "company-sso"}) in page
    assert str(NOT_SET_UP).replace("’", "&#x27;").split(":")[0] in page  # gitlab
    assert "test-github" not in page  # nothing from the credentials


@pytest.mark.django_db
def test_admins_switch_a_provider_on(superuser_client):
    provider = SocialProvider.objects.get(provider_id="company-sso")
    change = reverse("admin:capy_auth_socialprovider_change", args=[provider.pk])
    assert superuser_client.post(change, {"enabled": "on"}).status_code == 302
    assert "company-sso" in offered()


def test_a_provider_without_a_callback_address_shows_a_dash(monkeypatch):
    monkeypatch.setattr(admin_module.registry, "get_class", lambda provider_id: DummyProvider)
    assert admin_module.callback_path("dummy") is None
    monkeypatch.setattr(admin_module.registry, "get_class", lambda provider_id: None)
    assert admin_module.callback_path("not-set-up") == "/accounts/oidc/not-set-up/login/callback/"


@pytest.mark.django_db
def test_migrate_back_to_before_the_table_adds_nothing():
    from django.db import connection
    from django.db.migrations.loader import MigrationLoader

    before = MigrationLoader(connection).project_state(
        [("capy_auth", "0004_existing_users_email_addresses")]
    )
    add_new_providers(apps=before.apps)  # no table there: nothing to do, no error


def test_rows_come_from_the_settings_not_the_add_page(rf):
    assert SocialProviderAdmin(SocialProvider, admin.site).has_add_permission(rf.get("/")) is False


def test_allauths_page_that_stores_secrets_is_gone():
    assert not admin.site.is_registered(SocialApp)


# --- The checks ---------------------------------------------------------------------------


def test_without_capy_auths_social_adapter_the_site_doesnt_start(settings):
    assert checks.check_social_setup(None) == []
    settings.SOCIALACCOUNT_ADAPTER = "allauth.socialaccount.adapter.DefaultSocialAccountAdapter"
    assert [e.id for e in checks.check_social_setup(None)] == ["capy_auth.E013"]
    settings.SOCIALACCOUNT_ADAPTER = "no.such.Adapter"
    assert [e.id for e in checks.check_social_setup(None)] == ["capy_auth.E013"]


def test_without_allauths_social_app_the_site_doesnt_start(monkeypatch):
    monkeypatch.setattr(checks.apps, "is_installed", lambda name: False)
    assert [e.id for e in checks.check_social_setup(None)] == ["capy_auth.E013"]


def test_the_pretend_provider_is_refused_in_production(settings):
    assert checks.check_pretend_provider(None) == []
    settings.INSTALLED_APPS = [*settings.INSTALLED_APPS, checks.PRETEND_PROVIDER]
    assert [e.id for e in checks.check_pretend_provider(None)] == ["capy_auth.E014"]
    settings.DEBUG = True  # development
    assert checks.check_pretend_provider(None) == []


def test_storing_providers_tokens_gets_a_warning(settings):
    assert check_security_settings(None) == []
    settings.SOCIALACCOUNT_STORE_TOKENS = True
    [warning] = check_security_settings(None)
    assert "SOCIALACCOUNT_STORE_TOKENS" in warning.msg


def test_this_project_uses_capy_auths_social_adapter():
    assert isinstance(get_adapter(), adapter_module.SocialAccountAdapter)


def test_without_allauths_social_app_capy_auth_loads_none_of_it(monkeypatch):
    """A project missing the app gets E013, not a crash while loading capy-auth."""
    import capy_auth.admin

    installed = django_apps.is_installed
    monkeypatch.setattr(
        django_apps, "is_installed", lambda name: name != checks.SOCIAL_APP and installed(name)
    )
    try:
        django_apps.get_app_config("capy_auth").ready()  # connects nothing for social
        assert "SocialProviderAdmin" not in importlib.reload(capy_auth.admin).__all__
    finally:
        monkeypatch.undo()
        importlib.reload(capy_auth.admin)
