"""Signal receivers for MFA, connected in apps.py (connect_receivers)."""

from allauth.mfa.signals import authentication_failed, authenticator_added, authenticator_used

from .services import count_failed_code, forget_failed_codes
from .staff import remember_set_up


def failed_code(sender, user, reauthentication=False, **kwargs):
    if not reauthentication:  # signing in, not confirming a change while signed in
        count_failed_code(user)


def code_accepted(sender, user, **kwargs):
    forget_failed_codes(user)


def connect_receivers():
    authentication_failed.connect(failed_code, dispatch_uid="capy_auth_mfa_failed")
    authenticator_used.connect(code_accepted, dispatch_uid="capy_auth_mfa_used")
    authenticator_added.connect(remember_set_up, dispatch_uid="capy_auth_mfa_set_up")
