"""Staff and superusers must use two-step sign-in (capy_auth/mfa/staff.py). Tests about
other things sign staff in with `two_step_client`: an authenticator app set up for them
(allauth's own helper, not the pages, which have their own tests), then signed in and
confirmed with a code from it, as a person would."""

from allauth.mfa.totp.internal.auth import TOTP, generate_totp_secret
from django.test import Client
from django.urls import reverse

from tests import totp

CONFIRM_WITH_CODE = reverse("mfa_reauthenticate")


def two_step_client(user, client=None):
    """A client signed in as `user`, who has used two-step sign-in in this session."""
    client = client or Client()
    secret = generate_totp_secret()
    TOTP.activate(user, secret)
    client.force_login(user)
    response = client.post(CONFIRM_WITH_CODE, {"code": totp.code(secret)})
    assert response.status_code == 302, response.content.decode()[-2000:]
    return client
