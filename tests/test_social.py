"""Social sign-in's framework (capy_auth/social/, 14a of #33): providers set up in the
settings (tests/settings.py: GitHub, switched on by CAPY_AUTH_SOCIAL_PROVIDERS_ON, and a
company's OpenID Connect server, off), switched on and off on the Sign-in providers
page, database-stored apps ignored, and the checks E013 to E015 and W007. The admin page
and more ways to try to break it are in test_social_edges.py."""

import importlib
import secrets

import pytest
from allauth.core.exceptions import ImmediateHttpResponse
from allauth.socialaccount.adapter import _build_apps_from_settings, get_adapter
from allauth.socialaccount.models import SocialAccount, SocialApp, SocialLogin
from allauth.socialaccount.providers.dummy.provider import DummyProvider
from django.apps import apps as django_apps
from django.http import Http404
from django.urls import reverse

from capy_auth.config.checks import check_security_settings
from capy_auth.social import adapter as adapter_module
from capy_auth.social import checks
from capy_auth.social.models import SocialProvider
from capy_auth.social.services import add_new_providers

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
def test_a_switched_off_provider_is_not_found_at_its_sign_in_addresses(client):
    assert client.get(GITHUB_LOGIN).status_code == 200  # on: allauth's "continue" page
    switch("github", False)
    for path in (GITHUB_LOGIN, reverse("github_callback") + "?code=x&state=y"):
        assert client.get(path).status_code == 404


@pytest.mark.django_db
def test_a_sign_in_through_a_switched_off_provider_is_refused_when_it_answers(rf):
    """The last line of defense: allauth's hook once the provider has answered."""
    login = SocialLogin(account=SocialAccount(provider="github", uid="1"))
    get_adapter().pre_social_login(rf.get("/"), login)  # on: goes ahead
    switch("github", False)
    with pytest.raises(ImmediateHttpResponse) as refused:
        get_adapter().pre_social_login(rf.get("/"), login)
    assert refused.value.response.status_code == 404


@pytest.mark.django_db
def test_an_account_already_connected_still_finds_its_switched_off_provider(ada):
    """So people can see and remove it (the Connected accounts page)."""
    account = SocialAccount.objects.create(user=ada, provider="github", uid="1")
    switch("github", False)
    assert account.get_provider().id == "github"


@pytest.mark.django_db
def test_migrate_again_keeps_the_pages_choice_and_rows_of_providers_gone(settings):
    switch("github", False)
    SocialProvider.objects.create(provider_id="gitlab", enabled=True)  # no longer set up
    settings.CAPY_AUTH_SOCIAL_PROVIDERS_ON = ["github", "company-sso"]
    add_new_providers()
    states = dict(SocialProvider.objects.values_list("provider_id", "enabled"))
    assert states == {"github": False, "company-sso": False, "gitlab": True}
    assert offered() == set()  # github switched off; gitlab has no credentials to offer


@pytest.mark.django_db
def test_a_provider_with_an_empty_client_id_or_secret_isnt_set_up(settings):
    settings.SOCIALACCOUNT_PROVIDERS = {
        **settings.SOCIALACCOUNT_PROVIDERS,
        "github": {"APPS": [{"client_id": "test-github", "secret": ""}]},
    }
    assert offered() == set()
    assert [app.provider_id or app.provider for app in get_adapter().list_apps(None)] == [
        "company-sso"
    ]


@pytest.mark.django_db
def test_a_provider_stored_in_the_database_is_never_used(django_assert_num_queries):
    """allauth's SocialApp keeps the secret in the database: capy-auth ignores it, and
    doesn't even read its table."""
    stored = SocialApp.objects.create(
        provider="github", client_id="from-db", secret=secrets.token_urlsafe()
    )
    with django_assert_num_queries(0):
        apps = get_adapter().list_apps(None)
    assert [app.client_id for app in apps if app.provider == "github"] == ["test-github"]
    stored.delete()


@pytest.mark.django_db
def test_the_providers_are_read_without_querying_allauths_table(django_assert_num_queries):
    with django_assert_num_queries(0):
        apps = _build_apps_from_settings()  # allauth's own code capy-auth relies on
    ids = {app.provider_id or app.provider for found in apps.values() for app in found}
    assert ids == {"github", "company-sso"}


# --- allauth's pretend provider -----------------------------------------------------------


@pytest.fixture
def pretend(monkeypatch, rf):
    provider = DummyProvider(rf.get("/"), app=None)
    base = adapter_module.DefaultSocialAccountAdapter
    monkeypatch.setattr(base, "list_providers", lambda self, request: [provider])
    monkeypatch.setattr(base, "get_provider", lambda self, *args, **kwargs: provider)
    return provider


@pytest.mark.django_db
def test_the_pretend_provider_is_offered_only_when_switched_on(pretend):
    assert offered() == set()
    SocialProvider.objects.create(provider_id="dummy", enabled=True)
    assert offered() == {"dummy"}


@pytest.mark.django_db
def test_the_pretend_provider_is_refused_with_debug_off_and_found_in_development(pretend, settings):
    with pytest.raises(Http404):
        get_adapter().get_provider(None, "dummy")
    settings.DEBUG = True
    assert get_adapter().get_provider(None, "dummy") is pretend


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
    assert checks.check_pretend_provider(None) == []
    assert checks.check_starting_providers(None) == []  # E013 says what to do first


def test_the_pretend_provider_is_refused_with_debug_off_however_its_installed(
    monkeypatch, settings
):
    registry = importlib.import_module("allauth.socialaccount.providers").registry
    assert checks.check_pretend_provider(None) == []

    class Copy(DummyProvider):
        id = "copy"

    monkeypatch.setattr(registry, "get_class_list", lambda: [Copy])
    assert [e.id for e in checks.check_pretend_provider(None)] == ["capy_auth.E014"]
    settings.DEBUG = True  # development
    assert checks.check_pretend_provider(None) == []


@pytest.mark.parametrize("value", ["github", ["github", 3]])
def test_the_starting_providers_must_be_a_list_of_ids(settings, value):
    settings.CAPY_AUTH_SOCIAL_PROVIDERS_ON = value
    assert [e.id for e in checks.check_starting_providers(None)] == ["capy_auth.E015"]


@pytest.mark.django_db
def test_a_one_string_starting_value_switches_nothing_on(settings):
    SocialProvider.objects.all().delete()
    settings.CAPY_AUTH_SOCIAL_PROVIDERS_ON = "github"  # E015 says how to fix it
    add_new_providers()
    assert not SocialProvider.objects.get(provider_id="github").enabled


def test_a_starting_provider_that_isnt_set_up_gets_a_warning(settings):
    assert checks.check_starting_providers(None) == []
    settings.CAPY_AUTH_SOCIAL_PROVIDERS_ON = ["GitHub", "github"]
    [warning] = checks.check_starting_providers(None)
    assert warning.id == "capy_auth.W007" and "GitHub" in warning.msg


@pytest.mark.parametrize("name", ["SOCIALACCOUNT_STORE_TOKENS", "SOCIALACCOUNT_LOGIN_ON_GET"])
def test_weakened_social_settings_get_a_warning(settings, name):
    assert check_security_settings(None) == []
    setattr(settings, name, True)
    [warning] = check_security_settings(None)
    assert name in warning.msg


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
        django_apps.get_app_config("capy_auth").ready()  # loads no social code: no error
        assert "SocialProviderAdmin" not in importlib.reload(capy_auth.admin).__all__
    finally:
        monkeypatch.undo()
        importlib.reload(capy_auth.admin)
