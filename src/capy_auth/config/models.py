"""capy-auth's settings that admins change on the capy-auth settings page (in the Django
admin), kept as one record in the database."""

from django.db import models
from django.db.models import Q
from django.utils.translation import gettext_lazy as _


class BreachedPasswordCheck(models.TextChoices):
    """Whose new passwords are checked against Have I Been Pwned's breached passwords."""

    OFF = "off", _("nobody")
    STAFF = "staff", _("staff and superusers")
    EVERYONE = "everyone", _("everyone")


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
    breached_password_check = models.CharField(
        _("check breached passwords"),
        max_length=10,
        choices=BreachedPasswordCheck,
        db_default=BreachedPasswordCheck.EVERYONE,
        help_text=_(
            "Refuse new passwords that have appeared in a data breach (checked with Have "
            "I Been Pwned). While the check applies and the service can't be reached, new "
            'passwords aren\'t accepted (logins still work); choose "nobody" here during '
            "a long outage. Works only when the project has added capy-auth's check to its "
            "password rules (AUTH_PASSWORD_VALIDATORS)."
        ),
    )

    class Meta:
        verbose_name = _("capy-auth settings")
        verbose_name_plural = _("capy-auth settings")
        constraints = [
            # Backstop: there's only ever one record. 1 is SINGLETON_ID (Meta can't
            # see the class's own attributes).
            models.CheckConstraint(condition=Q(pk=1), name="capy_auth_authsettings_one_row"),
            models.CheckConstraint(
                condition=Q(breached_password_check__in=BreachedPasswordCheck.values),
                name="capy_auth_authsettings_breached_check_valid",
            ),
        ]

    def __str__(self):
        return str(self._meta.verbose_name)
