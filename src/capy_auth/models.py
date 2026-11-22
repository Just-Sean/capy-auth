"""Database models for this module. Each lives in its section and is listed here, where
Django looks for them.

To link to users, use settings.AUTH_USER_MODEL (never import a project's User):

    from django.conf import settings
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
"""

from capy_auth.bans.models import BannedEmail, BannedEmailAttempt, BannedSocialAccount
from capy_auth.config.models import AuthSettings
from capy_auth.social.models import SocialProvider

__all__ = [
    "AuthSettings",
    "BannedEmail",
    "BannedEmailAttempt",
    "BannedSocialAccount",
    "SocialProvider",
]
