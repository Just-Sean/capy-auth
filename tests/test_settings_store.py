"""capy-auth's settings record: one record, starting from the project's settings, changed
on the "capy-auth settings" page in the admin. Its first option closes signup."""

import secrets

import pytest
from django.contrib.admin.models import CHANGE, LogEntry
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.db import IntegrityError, transaction
from django.urls import reverse

from capy_auth.config.models import AuthSettings
from capy_auth.config.store import get_auth_settings
from tests.test_pages import check_page

PASSWORD = secrets.token_urlsafe()
SETTINGS_LIST = reverse("admin:capy_auth_authsettings_changelist")
SETTINGS_PAGE = reverse("admin:capy_auth_authsettings_change", args=[AuthSettings.SINGLETON_ID])


@pytest.fixture
def admin_client(client):
    admin = get_user_model().objects.create_superuser(
        username="admin", email="admin@example.com", password=PASSWORD
    )
    client.force_login(admin)
    return client


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


# --- The admin page ------------------------------------------------------------------


@pytest.mark.django_db
def test_the_settings_list_opens_the_one_record(admin_client):
    response = admin_client.get(SETTINGS_LIST)
    assert response.status_code == 302
    assert response.url == SETTINGS_PAGE
    assert admin_client.get(SETTINGS_PAGE).status_code == 200


@pytest.mark.django_db
def test_an_admin_closes_signup_and_the_change_is_recorded(admin_client):
    get_auth_settings()
    response = admin_client.post(SETTINGS_PAGE, {"_save": "Save"})  # box left unticked
    assert response.status_code == 302
    assert get_auth_settings().signup_open is False
    assert LogEntry.objects.filter(action_flag=CHANGE, object_id="1").exists()


@pytest.mark.django_db
def test_the_record_cant_be_added_or_deleted(admin_client):
    get_auth_settings()
    assert admin_client.get(reverse("admin:capy_auth_authsettings_add")).status_code == 403
    delete = reverse("admin:capy_auth_authsettings_delete", args=[AuthSettings.SINGLETON_ID])
    assert admin_client.post(delete, {"post": "yes"}).status_code == 403
    assert AuthSettings.objects.count() == 1


@pytest.mark.django_db
def test_staff_without_permission_cant_see_the_settings(client):
    staff = get_user_model().objects.create_user(
        username="staff", email="staff@example.com", password=PASSWORD, is_staff=True
    )
    client.force_login(staff)
    assert client.get(SETTINGS_LIST).status_code == 403
    assert client.get(SETTINGS_PAGE).status_code == 403


@pytest.mark.django_db
def test_staff_with_the_change_permission_can_change_the_settings(client):
    staff = get_user_model().objects.create_user(
        username="staff", email="staff@example.com", password=PASSWORD, is_staff=True
    )
    staff.user_permissions.add(Permission.objects.get(codename="change_authsettings"))
    client.force_login(staff)
    assert client.get(SETTINGS_LIST).url == SETTINGS_PAGE  # opening it makes the record
    assert client.post(SETTINGS_PAGE, {"_save": "Save"}).status_code == 302
    assert get_auth_settings().signup_open is False


# --- Closing signup ------------------------------------------------------------------


def close_signup():
    record = get_auth_settings()
    record.signup_open = False
    record.save()


@pytest.mark.django_db
def test_signup_is_open_by_default(client):
    page = check_page(client.get(reverse("account_signup")))
    assert 'name="password1"' in page


@pytest.mark.django_db
def test_closed_signup_shows_the_closed_page_and_creates_no_user(client):
    close_signup()
    page = check_page(client.get(reverse("account_signup")))
    assert "Sign Up Closed" in page
    assert 'name="password1"' not in page
    response = client.post(
        reverse("account_signup"),
        {
            "username": "eve",
            "email": "eve@example.com",
            "password1": PASSWORD,
            "password2": PASSWORD,
        },
    )
    check_page(response)
    assert not get_user_model().objects.filter(username="eve").exists()


@pytest.mark.django_db
def test_allauths_own_setting_still_closes_signup(client, settings):
    settings.ACCOUNT_SIGNUP_ENABLED = False
    assert get_auth_settings().signup_open is True
    assert "Sign Up Closed" in check_page(client.get(reverse("account_signup")))
