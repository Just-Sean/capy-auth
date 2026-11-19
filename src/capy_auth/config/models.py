"""capy-auth's settings that admins change on the capy-auth settings page (in the Django
admin), kept as one record in the database."""

from django.db import models
from django.db.models import Q
from django.utils.translation import gettext_lazy as _


class AuthSettings(models.Model):
    """The one record of capy-auth's settings. Read it with
    capy_auth.config.selectors.get_auth_settings(), which creates it the first time with
    starting values from the project's settings."""

    SINGLETON_ID = 1

    signup_open = models.BooleanField(
        _("signup open"),
        db_default=True,
        help_text=_(
            "Anyone can create an account. When off, the signup page says signup is "
            "closed and creates no accounts."
        ),
    )

    class Meta:
        verbose_name = _("capy-auth settings")
        verbose_name_plural = _("capy-auth settings")
        constraints = [
            # Backstop: there's only ever one record. 1 is SINGLETON_ID (Meta can't
            # see the class's own attributes).
            models.CheckConstraint(condition=Q(pk=1), name="capy_auth_authsettings_one_row"),
        ]

    def __str__(self):
        return str(self._meta.verbose_name)
