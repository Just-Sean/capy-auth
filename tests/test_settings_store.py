"""capy-auth's settings record: one record, starting from the project's settings, changed
on the "capy-auth settings" page in the admin. Its first option closes signup."""

import secrets

import pytest
from allauth.account.adapter import get_adapter
from allauth.socialaccount.adapter import get_adapter as get_social_adapter
from django.contrib import admin
from django.contrib.admin.models import CHANGE, LogEntry
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.management import call_command
from django.db import IntegrityError, transaction
from django.test import RequestFactory
from django.urls import reverse

from capy_auth.account.adapter import AccountAdapter
from capy_auth.config.checks import check_account_adapter, check_starting_values
from capy_auth.config.models import AuthSettings
from capy_auth.config.selectors import get_auth_settings
from tests.helpers import check_page

PASSWORD = secrets.token_urlsafe()
SIGNUP = reverse("account_signup")
SETTINGS_LIST = reverse("admin:capy_auth_authsettings_changelist")
SETTINGS_PAGE = reverse("admin:capy_auth_authsettings_change", args=[AuthSettings.SINGLETON_ID])
HISTORY_PAGE = reverse("admin:capy_auth_authsettings_history", args=[AuthSettings.SINGLETON_ID])
# The signup page's database queries once the settings record exists: reading it. A
# later feature that reads more must keep this small (README: Queries).
SIGNUP_PAGE_QUERIES = 1


@pytest.fixture
def superuser_client(client):
    superuser = get_user_model().objects.create_superuser(
        username="admin", email="admin@example.com", password=PASSWORD
    )
    client.force_login(superuser)
    return client


def log_in_staff(client, *permissions):
    """Logs in a staff user with only the given permissions (codenames)."""
    staff = get_user_model().objects.create_user(
        username="staff", email="staff@example.com", password=PASSWORD, is_staff=True
    )
    staff.user_permissions.add(*Permission.objects.filter(codename__in=permissions))
    client.force_login(staff)


def set_signup_open(value):
    record = get_auth_settings()
    record.signup_open = value
    record.save()


def signup_data(name="eve"):
    return {
        "username": name,
        "email": f"{name}@example.com",
        "password1": PASSWORD,
        "password2": PASSWORD,
    }


# --- The record ----------------------------------------------------------------------


@pytest.mark.django_db
def test_signup_starts_open_when_the_project_says_nothing(settings):
    del settings.CAPY_AUTH_SIGNUP_OPEN
    assert get_auth_settings().signup_open is True


@pytest.mark.django_db
def test_the_record_starts_from_the_projects_setting(settings):
    settings.CAPY_AUTH_SIGNUP_OPEN = False
    assert get_auth_settings().signup_open is False


@pytest.mark.django_db
def test_after_that_the_saved_value_wins_over_the_projects_setting(settings):
    settings.CAPY_AUTH_SIGNUP_OPEN = False
    get_auth_settings()
    settings.CAPY_AUTH_SIGNUP_OPEN = True
    assert get_auth_settings().signup_open is False


@pytest.mark.django_db
def test_there_is_only_ever_one_record():
    get_auth_settings()
    get_auth_settings()
    assert AuthSettings.objects.count() == 1
    with pytest.raises(IntegrityError), transaction.atomic():
        AuthSettings.objects.create(pk=2)


@pytest.mark.django_db
def test_a_deleted_record_comes_back_from_the_projects_setting(settings):
    settings.CAPY_AUTH_SIGNUP_OPEN = False
    get_auth_settings()
    AuthSettings.objects.all().delete()
    record = get_auth_settings()
    assert record.pk == AuthSettings.SINGLETON_ID
    assert record.signup_open is False


# --- Startup checks --------------------------------------------------------------------


def test_the_stand_in_project_passes_capy_auths_checks():
    call_command("check", "--fail-level", "ERROR")
    assert check_account_adapter(None) == []
    assert check_starting_values(None) == []


def test_a_project_without_capy_auths_adapter_gets_an_error(settings):
    settings.ACCOUNT_ADAPTER = "allauth.account.adapter.DefaultAccountAdapter"
    assert [error.id for error in check_account_adapter(None)] == ["capy_auth.E001"]


def test_a_projects_own_adapter_subclassing_capy_auths_passes(settings):
    settings.ACCOUNT_ADAPTER = "tests.test_settings_store.ProjectAdapter"
    assert check_account_adapter(None) == []


class ProjectAdapter(AccountAdapter):
    """A project's own adapter, built on capy-auth's."""


@pytest.mark.parametrize("value", ["false", "True", "0", None, 1])
def test_a_starting_value_that_isnt_true_or_false_gets_an_error(settings, value):
    settings.CAPY_AUTH_SIGNUP_OPEN = value
    assert [error.id for error in check_starting_values(None)] == ["capy_auth.E002"]


# --- The admin page ------------------------------------------------------------------


@pytest.mark.django_db
def test_the_settings_list_opens_the_one_record(superuser_client):
    response = superuser_client.get(SETTINGS_LIST, {"q": "x", "o": "1"})
    assert response.status_code == 302
    assert response.url == SETTINGS_PAGE
    assert superuser_client.get(SETTINGS_PAGE).status_code == 200


@pytest.mark.django_db
def test_an_admin_closes_signup_and_the_change_is_recorded(superuser_client):
    get_auth_settings()
    response = superuser_client.post(SETTINGS_PAGE, {"_save": "Save"})  # box left unticked
    assert response.status_code == 302
    assert get_auth_settings().signup_open is False
    assert LogEntry.objects.filter(action_flag=CHANGE, object_id="1").exists()


@pytest.mark.django_db
def test_the_record_cant_be_added_copied_or_deleted(superuser_client):
    get_auth_settings()
    assert superuser_client.get(reverse("admin:capy_auth_authsettings_add")).status_code == 403
    copy = superuser_client.post(SETTINGS_PAGE, {"_saveasnew": "1", "signup_open": "on"})
    assert copy.status_code == 403
    delete = reverse("admin:capy_auth_authsettings_delete", args=[AuthSettings.SINGLETON_ID])
    assert superuser_client.post(delete, {"post": "yes"}).status_code == 403
    superuser_client.post(
        SETTINGS_LIST, {"action": "delete_selected", "_selected_action": ["1"], "post": "yes"}
    )
    assert AuthSettings.objects.count() == 1


def test_the_bulk_delete_action_isnt_offered():
    request = RequestFactory().get(SETTINGS_LIST)
    request.user = get_user_model()(is_superuser=True, is_staff=True)
    assert "delete_selected" not in admin.site.get_model_admin(AuthSettings).get_actions(request)


@pytest.mark.django_db
def test_a_visitor_who_isnt_logged_in_is_sent_to_the_admin_login(client):
    response = client.get(SETTINGS_LIST)
    assert response.status_code == 302
    assert response.url.startswith(reverse("admin:login"))
    assert not AuthSettings.objects.exists()


@pytest.mark.django_db
def test_staff_without_permission_cant_see_the_settings_or_their_history(client):
    log_in_staff(client)
    get_auth_settings()
    assert client.get(SETTINGS_LIST).status_code == 403
    assert client.get(SETTINGS_PAGE).status_code == 403
    assert client.get(HISTORY_PAGE).status_code == 403


@pytest.mark.django_db
def test_staff_with_view_permission_see_the_settings_read_only(client):
    log_in_staff(client, "view_authsettings")
    assert client.get(SETTINGS_LIST).url == SETTINGS_PAGE
    page = client.get(SETTINGS_PAGE)
    assert page.status_code == 200
    assert 'name="signup_open"' not in page.content.decode()
    assert client.post(SETTINGS_PAGE, {"_save": "Save"}).status_code == 403
    assert get_auth_settings().signup_open is True
    assert client.get(HISTORY_PAGE).status_code == 200


@pytest.mark.django_db
def test_staff_with_the_change_permission_can_change_the_settings(client):
    log_in_staff(client, "change_authsettings")
    assert client.get(SETTINGS_LIST).url == SETTINGS_PAGE  # opening it makes the record
    assert client.post(SETTINGS_PAGE, {"_save": "Save"}).status_code == 302
    assert get_auth_settings().signup_open is False


# --- Closing signup ------------------------------------------------------------------


def test_allauth_uses_capy_auths_adapter():
    assert isinstance(get_adapter(), AccountAdapter)


@pytest.mark.django_db
def test_signup_is_open_by_default_and_reads_few_queries(client, django_assert_max_num_queries):
    get_auth_settings()  # the first visit also creates the record
    with django_assert_max_num_queries(SIGNUP_PAGE_QUERIES):
        page = check_page(client.get(SIGNUP))
    assert 'name="password1"' in page
    assert "Sign Up Closed" not in page


@pytest.mark.django_db
def test_open_signup_really_creates_a_user(client, settings):
    # Proves signup_data() is valid, so "no user" below means "closed".
    settings.ACCOUNT_EMAIL_VERIFICATION = "none"  # sending email comes with signup
    client.post(SIGNUP, signup_data())
    assert get_user_model().objects.filter(username="eve").exists()


@pytest.mark.django_db
def test_closed_signup_shows_the_closed_page_and_creates_no_user(client):
    set_signup_open(False)
    page = check_page(client.get(SIGNUP, {"next": "/admin/"}))
    assert "Sign Up Closed" in page
    assert 'name="password1"' not in page
    response = client.post(f"{SIGNUP}?next=/admin/", {**signup_data(), "next": "/admin/"})
    check_page(response)
    assert not get_user_model().objects.filter(username="eve").exists()


@pytest.mark.django_db
def test_closed_signup_creates_nobody_for_a_logged_in_user_either(client):
    client.force_login(
        get_user_model().objects.create_user(
            username="bob", email="bob@example.com", password=PASSWORD
        )
    )
    set_signup_open(False)
    client.post(SIGNUP, signup_data())
    assert not get_user_model().objects.filter(username="eve").exists()


@pytest.mark.django_db
def test_reopening_signup_takes_effect_on_the_next_request(client):
    set_signup_open(False)
    assert "Sign Up Closed" in client.get(SIGNUP).content.decode()
    set_signup_open(True)
    assert 'name="password1"' in client.get(SIGNUP).content.decode()


@pytest.mark.django_db
def test_social_signup_follows_the_same_switch():
    request = RequestFactory().get("/")
    assert get_social_adapter(request).is_open_for_signup(request, None) is True
    set_signup_open(False)
    assert get_social_adapter(request).is_open_for_signup(request, None) is False


@pytest.mark.django_db
def test_allauths_own_setting_still_closes_signup(client, settings):
    settings.ACCOUNT_SIGNUP_ENABLED = False
    assert get_auth_settings().signup_open is True
    assert "Sign Up Closed" in check_page(client.get(SIGNUP))
