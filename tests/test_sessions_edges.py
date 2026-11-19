"""Edge cases for asking again and the "Signed-in devices" page: every action that asks,
the 5-minute edge, sessions from the admin's login and from before the install,
password changes, other users, hostile or long browser descriptions, IPv6."""

import pytest
from allauth.account.authentication import AUTHENTICATION_METHODS_SESSION_KEY
from allauth.account.models import EmailAddress
from allauth.usersessions.models import UserSession
from django.contrib.sessions.models import Session
from django.test import Client
from django.urls import reverse

from tests.accounts import (
    ACCOUNT_PAGE,
    CHANGE_PASSWORD,
    LOGIN,
    LOGOUT,
    NEW_PASSWORD,
    PASSWORD,
    log_in,
)
from tests.helpers import check_page

SESSIONS_PAGE = reverse("usersessions_list")
EMAIL_PAGE = reverse("account_email")
REAUTHENTICATE = reverse("account_reauthenticate")
ADMIN_LOGIN = reverse("admin:login")
FIVE_MINUTES = 300


def signed_in(user_agent, **extra):
    client = Client(HTTP_USER_AGENT=user_agent, **extra)
    assert log_in(client).url == ACCOUNT_PAGE
    return client


def reauthenticate(client):
    client.post(REAUTHENTICATE, {"password": PASSWORD})


def typed_password_seconds_ago(client, seconds):
    session = client.session
    records = session[AUTHENTICATION_METHODS_SESSION_KEY]
    for record in records:
        record["at"] -= seconds
    session[AUTHENTICATION_METHODS_SESSION_KEY] = records
    session.save()


def admin_signed_in(user, user_agent="Admin browser/9.0"):
    client = Client(HTTP_USER_AGENT=user_agent)
    response = client.post(
        ADMIN_LOGIN,
        {"username": user.get_username(), "password": PASSWORD, "next": "/admin/"},
    )
    assert response.status_code == 302, response.content[:500]
    assert client.get("/admin/").status_code == 200
    return client


@pytest.fixture
def staff_ada(ada):
    ada.is_staff = True
    ada.is_superuser = True
    ada.save()
    return ada


@pytest.fixture
def second_address(ada):
    return EmailAddress.objects.create(
        user=ada, email="ada.work@example.com", verified=True, primary=False
    )


# --- Sessions that allauth never recorded ------------------------------------------------


@pytest.mark.django_db
def test_a_sign_in_on_the_admin_login_is_listed(staff_ada):
    admin_signed_in(staff_ada)
    laptop = signed_in("Laptop browser/2.0")
    page = check_page(laptop.get(SESSIONS_PAGE))
    assert "Admin browser/9.0" in page


@pytest.mark.django_db
def test_sign_out_everywhere_else_ends_an_admin_login_session(staff_ada):
    admin = admin_signed_in(staff_ada)
    laptop = signed_in("Laptop browser/2.0")
    phone = signed_in("Phone browser/1.0")
    laptop.post(SESSIONS_PAGE)
    assert phone.get(ACCOUNT_PAGE).status_code == 302
    assert admin.get(ACCOUNT_PAGE).status_code == 302  # should be signed out too


@pytest.mark.django_db
def test_a_device_signed_in_on_the_admins_login_is_listed_as_this_device(staff_ada):
    """This device signed in on the admin's login page; a phone through capy-auth's.
    Both are listed, this one marked, and the button signs out the phone."""
    phone = signed_in("Phone browser/1.0")
    admin = admin_signed_in(staff_ada)
    page = check_page(admin.get(SESSIONS_PAGE))
    assert "Phone browser/1.0" in page and "Admin browser/9.0" in page
    assert page.count("This device") == 1
    assert f'action="{SESSIONS_PAGE}"' in page
    admin.post(SESSIONS_PAGE)
    assert phone.get(ACCOUNT_PAGE).status_code == 302
    assert admin.get(ACCOUNT_PAGE).status_code == 200


@pytest.mark.django_db
def test_a_session_that_existed_before_tracking_is_listed(ada):
    """A project that adds capy-auth's sessions to a running site: people already
    signed in have no record. Simulated by deleting this session's record."""
    laptop = signed_in("Laptop browser/2.0")
    UserSession.objects.all().delete()
    page = check_page(laptop.get(SESSIONS_PAGE))
    assert "Laptop browser/2.0" in page
    assert "This device" in page


# --- Password change ------------------------------------------------------------------------


@pytest.mark.django_db
def test_after_a_password_change_other_sessions_end_and_leave_the_list(ada):
    phone = signed_in("Phone browser/1.0")
    laptop = signed_in("Laptop browser/2.0")
    response = laptop.post(
        CHANGE_PASSWORD,
        {"oldpassword": PASSWORD, "password1": NEW_PASSWORD, "password2": NEW_PASSWORD},
    )
    assert response.status_code == 302
    page = check_page(laptop.get(SESSIONS_PAGE))
    assert "Phone browser/1.0" not in page
    assert page.count("This device") == 1
    assert "Sign out everywhere else" not in page
    assert phone.get(ACCOUNT_PAGE).status_code == 302
    assert UserSession.objects.count() == 1


# --- Store rows and signing out -------------------------------------------------------------


@pytest.mark.django_db
def test_a_session_whose_store_row_was_deleted_is_not_listed(ada):
    phone = signed_in("Phone browser/1.0")
    laptop = signed_in("Laptop browser/2.0")
    Session.objects.filter(session_key=phone.session.session_key).delete()
    page = check_page(laptop.get(SESSIONS_PAGE))
    assert "Phone browser/1.0" not in page
    assert "Sign out everywhere else" not in page


@pytest.mark.django_db
def test_signing_out_removes_the_session_from_the_list(ada):
    phone = signed_in("Phone browser/1.0")
    laptop = signed_in("Laptop browser/2.0")
    phone.post(LOGOUT)
    page = check_page(laptop.get(SESSIONS_PAGE))
    assert "Phone browser/1.0" not in page


@pytest.mark.django_db
def test_posting_while_signed_out_ends_nothing(ada):
    phone = signed_in("Phone browser/1.0")
    response = Client().post(SESSIONS_PAGE)
    assert response.status_code == 302 and response.url.startswith(LOGIN)
    assert phone.get(ACCOUNT_PAGE).status_code == 200


@pytest.mark.django_db
def test_a_get_never_ends_sessions(ada):
    phone = signed_in("Phone browser/1.0")
    laptop = signed_in("Laptop browser/2.0")
    laptop.get(SESSIONS_PAGE)
    assert phone.get(ACCOUNT_PAGE).status_code == 200


@pytest.mark.django_db
def test_sign_out_everywhere_else_needs_csrf(ada):
    phone = signed_in("Phone browser/1.0")
    laptop = signed_in("Laptop")
    laptop.handler.enforce_csrf_checks = True
    assert laptop.post(SESSIONS_PAGE).status_code == 403
    assert phone.get(ACCOUNT_PAGE).status_code == 200


@pytest.mark.django_db
def test_sign_out_everywhere_else_with_only_this_session_keeps_it(client, ada):
    log_in(client)
    page = check_page(client.post(SESSIONS_PAGE, follow=True))
    assert client.get(ACCOUNT_PAGE).status_code == 200
    assert "This device" in page


@pytest.mark.django_db
def test_another_users_sessions_are_never_listed_or_ended(ada, django_user_model):
    bob = django_user_model.objects.create_user(
        username="bob", email="bob@example.com", password=PASSWORD
    )
    EmailAddress.objects.create(user=bob, email=bob.email, primary=True, verified=True)
    bob_client = Client(HTTP_USER_AGENT="Bob browser")
    log_in(bob_client, email="bob@example.com")
    laptop = signed_in("Laptop browser/2.0")
    page = check_page(laptop.get(SESSIONS_PAGE))
    assert "Bob browser" not in page
    laptop.post(SESSIONS_PAGE)
    assert bob_client.get(ACCOUNT_PAGE).status_code == 200


# --- What the page shows --------------------------------------------------------------------


@pytest.mark.django_db
def test_a_hostile_browser_description_is_escaped(ada):
    client = signed_in('<script>alert(1)</script><img src=x onerror="x">')
    page = check_page(client.get(SESSIONS_PAGE))
    assert "<script>alert(1)" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page


@pytest.mark.django_db
def test_a_very_long_browser_description_is_cut_and_still_signs_in(ada):
    client = signed_in("A" * 5000 + " ☃ emoji 🦫")
    page = check_page(client.get(SESSIONS_PAGE))
    max_length = UserSession._meta.get_field("user_agent").max_length
    assert "A" * max_length in page
    assert "A" * (max_length + 1) not in page


@pytest.mark.django_db
def test_an_ipv6_address_is_shown(ada):
    client = signed_in("Phone", REMOTE_ADDR="2001:db8::1")
    assert "IP address: 2001:db8::1" in check_page(client.get(SESSIONS_PAGE))


@pytest.mark.django_db
def test_sessions_are_listed_oldest_first(ada):
    signed_in("First browser")
    signed_in("Second browser")
    third = signed_in("Third browser")
    page = check_page(third.get(SESSIONS_PAGE))
    assert page.index("First browser") < page.index("Second browser") < page.index("Third browser")


# --- Reauthentication for each sensitive action ------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize("action", ["action_remove", "action_primary"])
def test_removing_or_making_primary_asks_again(client, ada, second_address, action):
    log_in(client)
    response = client.post(EMAIL_PAGE, {"email": second_address.email, action: ""})
    assert response.status_code == 302
    assert response.url.startswith(REAUTHENTICATE)
    second_address.refresh_from_db()
    assert EmailAddress.objects.filter(pk=second_address.pk, primary=False).exists()


@pytest.mark.django_db
@pytest.mark.parametrize("action", ["action_remove", "action_primary"])
def test_removing_or_making_primary_works_within_five_minutes(client, ada, second_address, action):
    log_in(client)
    reauthenticate(client)
    typed_password_seconds_ago(client, FIVE_MINUTES - 30)
    response = client.post(EMAIL_PAGE, {"email": second_address.email, action: ""})
    assert not response.url.startswith(REAUTHENTICATE)
    if action == "action_remove":
        assert not EmailAddress.objects.filter(pk=second_address.pk).exists()
    else:
        second_address.refresh_from_db()
        assert second_address.primary


@pytest.mark.django_db
def test_exactly_five_minutes_asks_again(client, ada):
    log_in(client)
    reauthenticate(client)
    typed_password_seconds_ago(client, FIVE_MINUTES)
    response = client.post(EMAIL_PAGE, {"email": "ada.work@example.com", "action_add": ""})
    assert response.url.startswith(REAUTHENTICATE)


@pytest.mark.django_db
def test_the_add_is_carried_out_after_typing_the_password(client, ada, mailoutbox):
    log_in(client)
    response = client.post(EMAIL_PAGE, {"email": "ada.work@example.com", "action_add": ""})
    assert response.url.startswith(REAUTHENTICATE)
    resumed = client.post(response.url, {"password": PASSWORD})
    # The suspended add is replayed: with verification by code, it goes on to the
    # code page and a code is emailed to the new address.
    assert resumed.url == reverse("account_email_verification_sent")
    assert any("ada.work@example.com" in m.to for m in mailoutbox)


@pytest.mark.django_db
def test_reauthentication_doesnt_survive_signing_out_and_in(client, ada):
    log_in(client)
    reauthenticate(client)
    client.post(LOGOUT)
    log_in(client)
    response = client.post(EMAIL_PAGE, {"email": "ada.work@example.com", "action_add": ""})
    assert response.url.startswith(REAUTHENTICATE)


@pytest.mark.django_db
def test_reauthentication_on_one_device_doesnt_count_on_another(ada):
    phone = signed_in("Phone")
    laptop = signed_in("Laptop")
    reauthenticate(phone)
    response = laptop.post(EMAIL_PAGE, {"email": "ada.work@example.com", "action_add": ""})
    assert response.url.startswith(REAUTHENTICATE)


@pytest.mark.django_db
def test_setting_a_password_asks_again(client, ada):
    """An account without a usable password (made by staff, not yet chosen) can't
    type one, so allauth asks for a code sent to its address instead."""
    ada.set_unusable_password()
    ada.save()
    client.force_login(ada, backend="allauth.account.auth_backends.AuthenticationBackend")
    response = client.get(reverse("account_set_password"))
    assert response.status_code == 302
    assert response.url.startswith(reverse("account_request_reauthentication_code"))


@pytest.mark.django_db
def test_resend_doesnt_need_reauthentication_but_is_allowed(client, ada):
    EmailAddress.objects.create(user=ada, email="ada.new@example.com", verified=False)
    log_in(client)
    response = client.post(EMAIL_PAGE, {"email": "ada.new@example.com", "action_send": ""})
    assert response.status_code == 302
    assert not response.url.startswith(REAUTHENTICATE)


@pytest.mark.django_db
def test_the_reauthenticate_page_is_in_the_layout(client, ada):
    log_in(client)
    check_page(client.get(REAUTHENTICATE))


@pytest.mark.django_db
def test_an_open_redirect_via_next_on_reauthenticate_is_refused(client, ada):
    log_in(client)
    response = client.post(REAUTHENTICATE + "?next=https://evil.example/", {"password": PASSWORD})
    assert response.status_code == 302
    assert "evil.example" not in response.url


# --- Bans --------------------------------------------------------------------------------


@pytest.mark.django_db
def test_a_suspended_account_cant_see_the_page(ada):
    phone = signed_in("Phone")
    ada.is_active = False
    ada.save()
    response = phone.get(SESSIONS_PAGE)
    assert response.status_code == 302
