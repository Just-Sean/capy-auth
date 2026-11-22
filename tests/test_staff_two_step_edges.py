"""Trying to break two-step sign-in for staff (from the QA review of #30): getting a
second step with only the password, other apps' pages that look open, the admin's own
links, requests of every kind, people who stop being staff, and where "next" leads."""

import pytest
from allauth.mfa.models import Authenticator
from allauth.mfa.recovery_codes.internal.auth import RecoveryCodes
from django.contrib.auth import SESSION_KEY
from django.contrib.auth.models import Group
from django.http import HttpResponse
from django.test import Client
from django.urls import include, path, reverse

from capy_auth.mfa import staff
from tests import totp
from tests.accounts import ACCOUNT_PAGE, LOGOUT, PASSWORD, log_in
from tests.staff import CONFIRM_WITH_CODE, make_staff, password_only, with_app
from tests.test_mfa import REAUTHENTICATE
from tests.test_passkeys import AJAX

ADMIN = "/admin/"
OTHER_APPS_LOGIN = "/other-apps-login/"
SET_UP = reverse("mfa_index")
CONFIRM_WITH_PASSKEY = reverse("mfa_reauthenticate_webauthn")
ADD_PASSKEY = reverse("mfa_add_webauthn")
SET_UP_NOTE = "Your account is a staff account, so it needs two-step sign-in before"


# --- Getting a second step with only the password ------------------------------------------


def with_app_and_codes(user):
    """An authenticator app and recovery codes, as setting it up on the pages leaves."""
    secret = with_app(user)
    RecoveryCodes.activate(user)
    return secret


def refused(response):
    """Sent to confirm with two-step sign-in instead."""
    return response.status_code == 302 and response.url.startswith(CONFIRM_WITH_CODE)


@pytest.fixture
def password_confirmed(ada):
    """Staff with an app and recovery codes, signed in and confirmed with the password
    alone: what someone with only the password can reach."""
    make_staff(ada, superuser=True)
    with_app_and_codes(ada)
    client = password_only(ada)
    assert refused(client.get(ADMIN))
    assert refused(client.post(REAUTHENTICATE, {"password": PASSWORD}))
    return client


@pytest.mark.django_db
def test_the_password_alone_cant_unlock_recovery_codes_to_confirm_with(password_confirmed):
    for page in ("mfa_view_recovery_codes", "mfa_download_recovery_codes"):
        assert refused(password_confirmed.get(reverse(page)))


@pytest.mark.django_db
def test_the_password_alone_cant_make_new_recovery_codes(ada, password_confirmed):
    before = Authenticator.objects.get(user=ada, type="recovery_codes").data
    assert refused(password_confirmed.post(reverse("mfa_generate_recovery_codes")))
    assert Authenticator.objects.get(user=ada, type="recovery_codes").data == before


@pytest.mark.django_db
def test_the_password_alone_cant_add_a_passkey_to_confirm_with(ada, password_confirmed):
    assert refused(password_confirmed.get(ADD_PASSKEY))
    assert refused(password_confirmed.post(ADD_PASSKEY, {"name": "Mine", "credential": "{}"}))
    assert not Authenticator.objects.filter(user=ada, type="webauthn").exists()


@pytest.mark.django_db
def test_the_password_alone_cant_turn_the_app_off_or_manage_keys(ada, password_confirmed):
    for page in ("mfa_deactivate_totp", "mfa_activate_totp", "mfa_list_webauthn"):
        assert refused(password_confirmed.post(reverse(page)))
    assert Authenticator.objects.filter(user=ada, type="totp").exists()
    assert refused(password_confirmed.get(ADMIN))


# --- Other apps' pages ---------------------------------------------------------------------


def project_report(request):
    return HttpResponse("staff-only numbers")


urlpatterns = [
    path("reports/mfa-usage/", project_report, name="mfa_usage_report"),
    path("", include("tests.urls")),
]


@pytest.mark.django_db
@pytest.mark.urls(__name__)
def test_a_project_page_named_like_a_two_step_page_isnt_open(ada):
    """A project's own page whose name happens to start with "mfa_"."""
    make_staff(ada)
    client = Client()
    log_in(client)
    assert client.get("/reports/mfa-usage/").status_code == 302


# --- Messages and the admin's own links ---------------------------------------------------


@pytest.mark.django_db
def test_the_reason_is_shown_once_however_many_pages_were_tried(ada):
    make_staff(ada)
    client = Client()
    log_in(client)
    for page in (ACCOUNT_PAGE, ADMIN, ACCOUNT_PAGE):
        client.get(page)
    page = client.get(SET_UP).content.decode()
    assert page.count(SET_UP_NOTE) == 1
    assert "Staff accounts need" not in page  # no message piled up per page tried


@pytest.mark.django_db
def test_the_admins_log_out_button_signs_staff_out_too(ada):
    make_staff(ada)
    client = Client()
    log_in(client)
    client.post(reverse("admin:logout"))
    assert SESSION_KEY not in client.session


@pytest.mark.django_db
def test_signing_out_from_allauth_still_works_with_a_next(ada):
    make_staff(ada)
    client = Client()
    log_in(client)
    client.post(LOGOUT + "?next=/admin/")
    assert SESSION_KEY not in client.session


# --- Requests of every kind ---------------------------------------------------------------


@pytest.mark.django_db
def test_posting_to_the_admin_without_two_step_changes_nothing(ada):
    make_staff(ada, superuser=True)
    with_app(ada)
    client = password_only(ada)
    response = client.post(reverse("admin:auth_group_add"), {"name": "Made without it"})
    assert response.status_code == 302 and response.url.startswith(CONFIRM_WITH_CODE)
    assert not Group.objects.exists()


@pytest.mark.django_db
def test_ajax_requests_are_stopped_too(ada):
    make_staff(ada)
    client = Client()
    log_in(client)
    assert client.get(ACCOUNT_PAGE, **AJAX).status_code == 302


@pytest.mark.django_db
def test_missing_pages_stay_missing(ada):
    make_staff(ada)
    client = Client()
    log_in(client)
    assert client.get("/no-such-page/").status_code == 404


# --- People who stop being staff, or can't sign in -----------------------------------------


@pytest.mark.django_db
def test_someone_no_longer_staff_is_let_go(ada):
    make_staff(ada)
    client = Client()
    log_in(client)
    assert client.get(ACCOUNT_PAGE).url == SET_UP
    make_staff(ada, staff=False)
    assert client.get(ACCOUNT_PAGE).status_code == 200


@pytest.mark.django_db
def test_inactive_staff_are_signed_out_not_sent_to_set_up(ada):
    make_staff(ada)
    client = Client()
    log_in(client)
    ada.is_active = False
    ada.save()
    response = client.get(ACCOUNT_PAGE)
    assert response.status_code == 302 and response.url != SET_UP


@pytest.mark.django_db
def test_another_persons_second_step_doesnt_count(ada, django_user_model):
    """A second step in this session, then someone else signs in through another app."""
    other = django_user_model.objects.create_user(
        username="bea", email="bea@example.com", password=PASSWORD
    )
    secret = with_app(other)
    client = Client()
    client.force_login(other)
    client.post(CONFIRM_WITH_CODE, {"code": totp.code(secret)})
    make_staff(ada)
    with_app(ada)
    client.post(OTHER_APPS_LOGIN, {"email": ada.email, "password": PASSWORD})
    assert client.get(ADMIN).url.startswith(CONFIRM_WITH_CODE)


# --- Where "next" leads -------------------------------------------------------------------


@pytest.mark.django_db
def test_confirming_never_leads_off_the_site(ada):
    make_staff(ada)
    secret = with_app(ada)
    client = Client()
    client.force_login(ada)
    response = client.post(
        CONFIRM_WITH_CODE + "?next=https://evil.example/", {"code": totp.code(secret)}
    )
    assert response.status_code == 302 and "evil.example" not in response.url


@pytest.mark.django_db
def test_next_keeps_the_query_string(ada):
    make_staff(ada)
    with_app(ada)
    client = Client()
    client.force_login(ada)
    response = client.get(ACCOUNT_PAGE + "?tab=a&b=c")
    assert response.url == f"{CONFIRM_WITH_CODE}?next=%2Faccounts%2Fprofile%2F%3Ftab%3Da%26b%3Dc"


def test_continue_never_leads_off_the_site(rf):
    """A request for "//other.example/" (no page answers it here, but a project's
    catch-all page might) isn't remembered as where to continue to."""
    request = rf.get("/")
    request.path = "//evil.example/x"  # as a raw HTTP request can ask (rf tidies it)
    request.session = {}
    staff.remember_destination(request)
    assert staff.NEXT_SESSION_KEY not in request.session
    request = rf.get("/admin/?q=1")
    request.session = {}
    staff.remember_destination(request)
    assert request.session[staff.NEXT_SESSION_KEY] == "/admin/?q=1"


def test_setting_up_counts_only_for_the_person_signed_in(rf, django_user_model):
    """allauth's signal without a request (made outside a page) or for someone else."""
    ada, bea = django_user_model(pk=1), django_user_model(pk=2)
    staff.remember_set_up(sender=None, request=None, user=ada)  # nothing to record on
    request = rf.get("/")
    request.session, request.user = {}, bea
    staff.remember_set_up(sender=None, request=request, user=ada)
    assert staff.SET_UP_SESSION_KEY not in request.session
