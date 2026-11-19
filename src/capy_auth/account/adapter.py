"""capy-auth's account adapter: allauth asks it how to behave. A project points
ACCOUNT_ADAPTER at it (see the README)."""

from allauth.account.adapter import DefaultAccountAdapter

from capy_auth.config.store import get_auth_settings


class AccountAdapter(DefaultAccountAdapter):
    def is_open_for_signup(self, request):
        """Open only when allauth's own setting allows it and admins haven't closed
        signup on the dashboard."""
        return super().is_open_for_signup(request) and get_auth_settings().signup_open
