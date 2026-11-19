"""The module's admin pages. Each lives in its section and is listed here, where Django
looks for them."""

from capy_auth.bans.admin import BannedEmailAdmin, BannedEmailAttemptAdmin, BannedSocialAccountAdmin
from capy_auth.config.admin import AuthSettingsAdmin

__all__ = [
    "AuthSettingsAdmin",
    "BannedEmailAdmin",
    "BannedEmailAttemptAdmin",
    "BannedSocialAccountAdmin",
]
