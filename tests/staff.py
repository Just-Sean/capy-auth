"""Staff and superusers must use two-step sign-in (capy_auth/mfa/staff.py). Tests about
other things sign staff in with `two_step_client`: an authenticator app set up for them
(allauth's own helper, not the pages, which have their own tests), then signed in and
confirmed with a code from it, as a person would. The staff tests also use the others."""

from allauth.mfa.totp.internal.auth import TOTP, generate_totp_secret
from django.contrib.auth import SESSION_KEY
from django.test import Client
from django.urls import reverse

from tests import totp
from tests.accounts import PASSWORD

CONFIRM_WITH_CODE = reverse("mfa_reauthenticate")
OTHER_APPS_LOGIN = "/other-apps-login/"  # tests/urls.py


def make_staff(user, staff=True, superuser=False):
    """Staff, or a superuser (who needs staff too to open the admin)."""
    user.is_staff = staff
    user.is_superuser = superuser
    user.save()
    return user


def with_app(user):
    """Sets up an authenticator app for `user`; returns its secret."""
    secret = generate_totp_secret()
    TOTP.activate(user, secret)
    return secret


def password_only(user):
    """Signed in through another app's login page (Django's login(), not allauth's), so
    with the password alone: the session has no second step."""
    client = Client()
    client.post(OTHER_APPS_LOGIN, {"email": user.email, "password": PASSWORD})
    assert client.session[SESSION_KEY] == str(user.pk)
    return client


def two_step_client(user, client=None):
    """A client signed in as `user`, who has used two-step sign-in in this session."""
    client = client or Client()
    secret = with_app(user)
    client.force_login(user)
    response = client.post(CONFIRM_WITH_CODE, {"code": totp.code(secret)})
    assert response.status_code == 302, response.content.decode()[-2000:]
    return client
