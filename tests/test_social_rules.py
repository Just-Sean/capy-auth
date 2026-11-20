"""Social sign-in's rules (#35): the ban list for provider sign-ins (a banned account at
the provider, or a banned email it gives), no joining accounts by email, signup closed
for provider signups too, and allauth's social pages inside the layout."""

import pytest
from allauth.account.models import EmailAddress
from allauth.core.exceptions import ImmediateHttpResponse
from allauth.socialaccount.adapter import get_adapter
from allauth.socialaccount.models import SocialAccount, SocialLogin
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.contrib.sessions.middleware import SessionMiddleware
from django.urls import reverse

from capy_auth.bans.models import BannedEmail, BannedEmailAttempt, BannedSocialAccount
from capy_auth.config.checks import check_security_settings
from capy_auth.config.selectors import get_auth_settings
from tests.helpers import check_page

BANNED = "mallory@example.com"


@pytest.fixture
def request_(rf):
    request = rf.get("/accounts/github/login/callback/")
    SessionMiddleware(lambda r: None).process_request(request)
    request.user = AnonymousUser()
    return request


def provider_login(email="new@example.com", uid="42", user=None):
    """What allauth has once GitHub answers: the account there, and the emails it gave."""
    login = SocialLogin(
        user=user or get_user_model()(email=email),
        account=SocialAccount(provider="github", uid=uid, user=user),
        email_addresses=[EmailAddress(email=email, verified=True)],
    )
    return login


def refused(request, login):
    with pytest.raises(ImmediateHttpResponse) as caught:
        get_adapter().pre_social_login(request, login)
    page = caught.value.response.content.decode()
    assert "ban" not in page.lower()  # nothing says why, as at email signup
    return page


@pytest.mark.django_db
def test_a_clean_provider_sign_in_goes_ahead(request_):
    get_adapter().pre_social_login(request_, provider_login())


@pytest.mark.django_db
def test_a_banned_account_at_the_provider_is_refused(request_):
    BannedSocialAccount.objects.create(provider="github", uid="42")
    refused(request_, provider_login())
    assert not BannedEmailAttempt.objects.exists()  # an ID, not an address


@pytest.mark.django_db
def test_a_new_account_with_a_banned_email_is_refused_and_recorded(request_):
    BannedEmail.objects.create(email=BANNED)
    refused(request_, provider_login(email="Mallory@Example.com"))
    assert list(BannedEmailAttempt.objects.values_list("email", "kind")) == [(BANNED, "signup")]


@pytest.mark.django_db
def test_an_existing_connection_with_a_banned_email_is_refused_unrecorded(request_, ada):
    BannedEmail.objects.create(email=BANNED)
    SocialAccount.objects.create(user=ada, provider="github", uid="7")
    login = provider_login(email=BANNED, uid="7", user=ada)
    assert login.is_existing  # an account already here signing in
    refused(request_, login)
    assert not BannedEmailAttempt.objects.exists()


@pytest.mark.django_db
def test_closed_signup_closes_provider_signups_too(request_):
    record = get_auth_settings()
    record.signup_open = False
    record.save()
    assert get_adapter().is_open_for_signup(request_, provider_login()) is False


@pytest.mark.parametrize(
    "name",
    ["SOCIALACCOUNT_EMAIL_AUTHENTICATION", "SOCIALACCOUNT_EMAIL_AUTHENTICATION_AUTO_CONNECT"],
)
def test_joining_accounts_by_email_gets_a_warning(settings, name):
    assert check_security_settings(None) == []
    setattr(settings, name, True)
    [warning] = check_security_settings(None)
    assert name in warning.msg


# --- allauth's social pages, inside the layout --------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize("connected", [False, True])
def test_the_connected_accounts_page_is_in_the_layout(client, ada, connected):
    if connected:
        SocialAccount.objects.create(user=ada, provider="github", uid="1")
    client.force_login(ada)
    page = check_page(client.get(reverse("socialaccount_connections")))
    assert ('name="account"' in page) is connected  # the connection to remove
    assert "?process=connect" in page  # and providers to connect


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("name", "status"), [("socialaccount_login_error", 401), ("socialaccount_login_cancelled", 200)]
)
def test_the_error_pages_are_in_the_layout(client, name, status):
    check_page(client.get(reverse(name)), status=status)
