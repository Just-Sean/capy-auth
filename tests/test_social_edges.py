"""Trying to break social sign-in's framework (from the QA review of #33), and the
admin's Sign-in providers page: switched-off, unknown and look-alike addresses,
database-stored apps, people already connected, who can use the page, and what it shows."""

import secrets

import pytest
from allauth.core import context
from allauth.socialaccount.adapter import get_adapter
from allauth.socialaccount.models import SocialAccount, SocialApp
from django.contrib import admin
from django.contrib.auth.models import Permission
from django.test import Client
from django.urls import reverse

from capy_auth.social import admin as admin_module
from capy_auth.social.admin import NOT_SET_UP, SocialProviderAdmin
from capy_auth.social.models import SocialProvider
from capy_auth.social.services import add_new_providers
from tests.accounts import PASSWORD, log_in
from tests.staff import make_staff, two_step_client
from tests.test_social import switch

PROVIDERS_PAGE = reverse("admin:capy_auth_socialprovider_changelist")
CONNECTIONS = reverse("socialaccount_connections")


def change_page(provider_id):
    pk = SocialProvider.objects.get(provider_id=provider_id).pk
    return reverse("admin:capy_auth_socialprovider_change", args=[pk])


# --- Addresses ------------------------------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize(
    "path",
    [
        reverse("github_callback") + "?code=x&state=y",
        "/accounts/oidc/company-sso/login/",
        "/accounts/oidc/company-sso/login/callback/?code=x&state=y",
        "/accounts/oidc/openid_connect/login/",  # the class id instead of the provider_id
        "/accounts/oidc/COMPANY-SSO/login/",
        "/accounts/oidc/no-such-server/login/",
        "/accounts/oidc/GitHub/login/",
    ],
)
def test_switched_off_or_unknown_provider_addresses_are_not_found(client, path):
    switch("github", False)
    assert client.get(path).status_code == 404


@pytest.mark.django_db
def test_a_database_app_for_an_oidc_id_is_never_used(client):
    """An old install left an OpenID Connect app in allauth's table, and a switched-on
    row has its id: still nothing to sign in with."""
    SocialApp.objects.create(
        provider="openid_connect",
        provider_id="evil-sso",
        name="Evil",
        client_id="evil",
        secret=secrets.token_urlsafe(),
        settings={"server_url": "https://evil.example.com"},
    )
    SocialProvider.objects.create(provider_id="evil-sso", enabled=True)
    assert get_adapter().list_apps(None, provider="evil-sso") == []
    assert client.get("/accounts/oidc/evil-sso/login/").status_code == 404


@pytest.mark.django_db
def test_a_database_app_with_the_settings_id_doesnt_clash():
    SocialApp.objects.create(provider="github", client_id="db", secret=secrets.token_urlsafe())
    assert get_adapter().get_app(None, "github").client_id == "test-github"


@pytest.mark.django_db
def test_two_switched_on_oidc_servers_at_the_class_id_are_not_a_server_error(client, settings):
    providers = dict(settings.SOCIALACCOUNT_PROVIDERS)
    first = providers["openid_connect"]["APPS"][0]
    providers["openid_connect"] = {"APPS": [first, dict(first, provider_id="other-sso")]}
    settings.SOCIALACCOUNT_PROVIDERS = providers
    add_new_providers()
    switch("company-sso", True)
    switch("other-sso", True)
    client.raise_request_exception = False
    assert client.get("/accounts/oidc/openid_connect/login/").status_code == 404


# --- People already connected to a switched-off provider ----------------------------------


@pytest.fixture
def linked_ada(ada):
    SocialAccount.objects.create(user=ada, provider="github", uid="1001", extra_data={})
    return ada


@pytest.mark.django_db
def test_their_connected_accounts_page_still_opens(client, linked_ada):
    client.force_login(linked_ada)
    switch("github", False)
    assert client.get(CONNECTIONS).status_code == 200


@pytest.mark.django_db
@pytest.mark.parametrize("on", [True, False])
def test_they_can_still_remove_the_connection(client, linked_ada, on):
    log_in(client)
    client.post(reverse("account_reauthenticate"), {"password": PASSWORD})
    account = SocialAccount.objects.get(user=linked_ada)
    switch("github", on)
    response = client.post(CONNECTIONS, {"account": account.pk})
    assert response.status_code == 302 and response["Location"] == CONNECTIONS
    assert not SocialAccount.objects.filter(pk=account.pk).exists()


@pytest.mark.django_db
def test_their_password_sign_in_still_works(client, linked_ada):
    switch("github", False)
    assert log_in(client).status_code == 302
    assert client.get(reverse("capy_auth_account")).status_code == 200


# --- Reading the switches -------------------------------------------------------------------


@pytest.mark.django_db
def test_one_request_reads_the_switches_once(rf):
    request = rf.get("/")
    with context.request_context(request):
        assert {p.sub_id for p in get_adapter().list_providers(request)} == {"github"}
        switch("github", False)
        assert {p.sub_id for p in get_adapter().list_providers(request)} == {"github"}
    with context.request_context(rf.get("/")):
        assert get_adapter().list_providers(None) == []


@pytest.mark.django_db
def test_the_sign_in_page_shows_only_switched_on_buttons(client):
    page = client.get(reverse("account_login")).content.decode()
    assert reverse("github_login") in page and "/oidc/company-sso/login/" not in page
    switch("github", False)
    switch("company-sso", True)
    page = client.get(reverse("account_login")).content.decode()
    assert reverse("github_login") not in page and "/oidc/company-sso/login/" in page


# --- The Sign-in providers page -----------------------------------------------------------


@pytest.fixture
def root_client(django_user_model):
    root = django_user_model.objects.create_superuser(
        username="root", email="root@example.com", password=PASSWORD
    )
    return two_step_client(root)


@pytest.mark.django_db
def test_the_page_lists_providers_and_where_to_register_them(root_client):
    SocialProvider.objects.create(provider_id="gitlab")  # no longer set up
    page = root_client.get(PROVIDERS_PAGE).content.decode()
    assert "GitHub" in page and "Company sign-in" in page  # each server's own name
    assert reverse("github_callback") in page
    assert "/accounts/oidc/company-sso/login/callback/" in page
    assert "/accounts/oidc/gitlab/" not in page  # no made-up address for gitlab
    assert "whoever runs the site adds its client ID" in page
    assert "test-github" not in page  # nothing from the credentials


@pytest.mark.django_db
def test_admins_switch_a_provider_on_its_own_labelled_page(root_client):
    page = root_client.get(change_page("company-sso")).content.decode()
    assert '<label class="vCheckboxLabel" for="id_enabled">' in page
    assert "Company sign-in" in page and "Forgot your password" in page
    assert root_client.post(change_page("company-sso"), {"enabled": "on"}).status_code == 302
    assert SocialProvider.objects.get(provider_id="company-sso").enabled


@pytest.mark.django_db
def test_a_provider_that_isnt_set_up_cant_be_switched_on(root_client):
    SocialProvider.objects.create(provider_id="gitlab")
    root_client.post(change_page("gitlab"), {"enabled": "on"})
    assert not SocialProvider.objects.get(provider_id="gitlab").enabled


@pytest.mark.django_db
def test_only_rows_no_longer_set_up_can_be_deleted(root_client):
    SocialProvider.objects.create(provider_id="gitlab")
    github = SocialProvider.objects.get(provider_id="github")
    delete = reverse("admin:capy_auth_socialprovider_delete", args=[github.pk])
    assert root_client.post(delete, {"post": "yes"}).status_code == 403
    gitlab = SocialProvider.objects.get(provider_id="gitlab")
    delete = reverse("admin:capy_auth_socialprovider_delete", args=[gitlab.pk])
    assert root_client.post(delete, {"post": "yes"}).status_code == 302
    assert set(SocialProvider.objects.values_list("provider_id", flat=True)) == {
        "github",
        "company-sso",
    }


@pytest.mark.django_db
def test_secrets_left_in_allauths_table_are_pointed_out(root_client):
    assert "client secrets are stored" not in root_client.get(PROVIDERS_PAGE).content.decode()
    SocialApp.objects.create(provider="github", client_id="old", secret=secrets.token_urlsafe())
    page = root_client.get(PROVIDERS_PAGE).content.decode()
    assert "client secrets are stored in the database" in page


@pytest.fixture
def staff_member(django_user_model):
    return make_staff(
        django_user_model.objects.create_user(
            username="sam", email="sam@example.com", password=PASSWORD
        )
    )


@pytest.mark.django_db
def test_staff_without_permission_cant_open_the_page(staff_member):
    assert two_step_client(staff_member).get(PROVIDERS_PAGE).status_code == 403


@pytest.mark.django_db
def test_view_only_staff_cant_switch_a_provider(staff_member):
    staff_member.user_permissions.add(Permission.objects.get(codename="view_socialprovider"))
    staff_client = two_step_client(staff_member)
    assert staff_client.get(PROVIDERS_PAGE).status_code == 200
    assert staff_client.post(change_page("company-sso"), {"enabled": "on"}).status_code == 403
    assert not SocialProvider.objects.get(provider_id="company-sso").enabled


@pytest.mark.django_db
def test_anonymous_people_are_sent_to_sign_in():
    assert Client().get(PROVIDERS_PAGE).status_code == 302


@pytest.mark.django_db
def test_the_provider_id_cant_be_changed(root_client):
    root_client.post(change_page("company-sso"), {"provider_id": "github", "enabled": "on"})
    assert SocialProvider.objects.filter(provider_id="company-sso").exists()


def test_rows_come_from_the_settings_not_an_add_page_or_bulk_delete(rf):
    model_admin = SocialProviderAdmin(SocialProvider, admin.site)
    assert model_admin.has_add_permission(rf.get("/")) is False
    assert model_admin.actions is None  # no bulk delete


def test_allauths_page_that_stores_secrets_is_gone():
    assert not admin.site.is_registered(SocialApp)
    site = admin.AdminSite(name="project_already_removed_it")
    admin_module.remove_allauths_secret_page(site)  # nothing to remove: no error
    assert not site.is_registered(SocialApp)


def test_a_provider_without_a_callback_address_has_none(monkeypatch):
    from allauth.socialaccount.providers.dummy.provider import DummyProvider

    monkeypatch.setattr(admin_module.registry, "get_class", lambda provider_id: DummyProvider)
    assert admin_module.callback_path("dummy") is None


def test_the_not_set_up_text_says_who_fixes_it():
    assert "whoever runs the site" in str(NOT_SET_UP)


@pytest.mark.django_db
def test_migrate_back_to_before_the_table_adds_nothing():
    from django.db import connection
    from django.db.migrations.loader import MigrationLoader

    before = MigrationLoader(connection).project_state(
        [("capy_auth", "0004_existing_users_email_addresses")]
    )
    add_new_providers(apps=before.apps)  # no table there: nothing to do, no error
