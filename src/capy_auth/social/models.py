"""Which set-up sign-in providers (Google, GitHub, a company's OpenID Connect server…)
are offered. A provider is set up in the project's settings, with its client ID and
secret from environment variables; this table only says whether it's switched on, so
no secret is ever stored in the database."""

from django.db import models
from django.utils.translation import gettext_lazy as _


class SocialProvider(models.Model):
    # allauth's id for the provider ("google"), or the provider_id of an OpenID Connect
    # server set up in the settings ("company-sso").
    provider_id = models.CharField(_("provider"), max_length=200, unique=True)
    enabled = models.BooleanField(
        _("switched on"),
        default=False,
        help_text=_("Offer this provider on the sign-in and signup pages."),
    )

    class Meta:
        ordering = ["provider_id"]
        verbose_name = _("sign-in provider")
        verbose_name_plural = _("sign-in providers")

    def __str__(self):
        return self.provider_id
