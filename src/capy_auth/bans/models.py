"""The ban list: email addresses and social accounts that can't be used for an account
here, and the attempts to use a banned address anyway, for staff to look at."""

from django.conf import settings
from django.db import models
from django.db.models.functions import Lower
from django.utils.translation import gettext_lazy as _


def normalize_email(email):
    """The one way an address is written in the ban list and when checking it: no spaces
    around it, lowercase, and an international domain in its ASCII form (punycode), so
    "bücher.example" and "xn--bcher-kva.example" match. A domain that can't be encoded
    is kept as typed."""
    email = (email or "").strip().lower()
    local, at, domain = email.rpartition("@")
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        return email
    return f"{local}{at}{domain}"


class BannedEmail(models.Model):
    """An email address nobody can sign up with or add to an account. Saved normalized
    (normalize_email), so it matches however it's typed; the database refuses anything
    not in lowercase."""

    email = models.EmailField(_("email address"), unique=True)
    reason = models.TextField(
        _("reason"), blank=True, help_text=_("A note for staff; never shown to the person.")
    )
    created_at = models.DateTimeField(_("banned at"), auto_now_add=True)
    suspended_accounts = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        blank=True,
        editable=False,
        related_name="+",
        verbose_name=_("accounts it suspended"),
    )

    class Meta:
        verbose_name = _("banned email address")
        verbose_name_plural = _("banned email addresses")
        constraints = [
            models.CheckConstraint(
                condition=models.Q(email=Lower("email")), name="capy_auth_bannedemail_lowercase"
            ),
        ]

    def __str__(self):
        return self.email

    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)

    def clean(self):
        self.email = normalize_email(self.email)


class BannedSocialAccount(models.Model):
    """A social login (a provider's account ID) that can't be used here. Checked from
    capy-auth's social login support."""

    provider = models.CharField(
        _("provider"), max_length=200, help_text=_('allauth\'s provider ID, e.g. "google".')
    )
    uid = models.CharField(
        _("account ID"), max_length=191, help_text=_("The person's ID at that provider.")
    )
    reason = models.TextField(
        _("reason"), blank=True, help_text=_("A note for staff; never shown to the person.")
    )
    created_at = models.DateTimeField(_("banned at"), auto_now_add=True)

    class Meta:
        verbose_name = _("banned social account")
        verbose_name_plural = _("banned social accounts")
        constraints = [
            models.UniqueConstraint(
                fields=["provider", "uid"], name="capy_auth_bannedsocialaccount_unique"
            ),
        ]

    def __str__(self):
        return f"{self.provider}: {self.uid}"


class AttemptKind(models.TextChoices):
    SIGNUP = "signup", _("Sign up")
    ADD_EMAIL = "add_email", _("Add to an account")


class BannedEmailAttempt(models.Model):
    """Someone tried to use a banned address. Kept for staff, who decide what to do;
    nothing happens to the account automatically."""

    email = models.EmailField(_("banned address tried"))
    kind = models.CharField(_("what was tried"), max_length=20, choices=AttemptKind)
    account = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
        verbose_name=_("account"),
        help_text=_("The account that tried to add the address."),
    )
    ip_address = models.GenericIPAddressField(_("IP address"), null=True, blank=True)
    created_at = models.DateTimeField(_("tried at"), auto_now_add=True)

    class Meta:
        verbose_name = _("banned address attempt")
        verbose_name_plural = _("banned address attempts")
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["-created_at"], name="capy_auth_attempt_created_idx"),
        ]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(kind__in=AttemptKind.values),
                name="capy_auth_bannedemailattempt_kind_valid",
            ),
        ]

    def __str__(self):
        return f"{self.get_kind_display()}: {self.email}"
