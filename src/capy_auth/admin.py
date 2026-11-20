"""The module's admin pages. Each lives in its section and is listed here, where Django
looks for them."""

from django.apps import apps

from capy_auth.bans.admin import BannedEmailAdmin, BannedEmailAttemptAdmin, BannedSocialAccountAdmin
from capy_auth.config.admin import AuthSettingsAdmin

__all__ = [
    "AuthSettingsAdmin",
    "BannedEmailAdmin",
    "BannedEmailAttemptAdmin",
    "BannedSocialAccountAdmin",
]
if apps.is_installed("allauth.socialaccount"):  # without it, Django's checks say so (E013)
    from capy_auth.social.admin import SocialProviderAdmin

    __all__ += ["SocialProviderAdmin"]
