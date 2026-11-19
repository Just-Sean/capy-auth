"""Django system check: capy-auth can't work without email (signup codes, password
resets), so a production site whose email can't be sent is stopped at startup."""

from django.conf import settings
from django.core.checks import Error

# Backends that send nothing: Django's dummy one, and capy-project's stand-in when
# EMAIL_URL isn't set (it raises "Email isn't set up").
NO_EMAIL_BACKENDS = {"django.core.mail.backends.dummy.EmailBackend"}
NOT_SET_UP_SUFFIX = ".EmailNotSetUpBackend"


def mailer_backend():
    """The default mailer's backend, from Django 6.1's MAILERS (as capy-project sets it).
    A project still on the older EMAIL_BACKEND setting isn't checked: reading it is
    deprecated."""
    return getattr(settings, "MAILERS", {}).get("default", {}).get("BACKEND", "")


def check_email_can_be_sent(app_configs, **kwargs):
    if settings.DEBUG:
        return []
    backend = mailer_backend()
    if backend not in NO_EMAIL_BACKENDS and not backend.endswith(NOT_SET_UP_SUFFIX):
        return []
    return [
        Error(
            f"capy-auth needs email (signup codes, password resets), but the default "
            f"mailer ({backend}) sends nothing.",
            hint="Set up email: in a project made from capy-project, set EMAIL_URL and "
            "DJANGO_DEFAULT_FROM_EMAIL (its README's Email section).",
            id="capy_auth.E004",
        )
    ]
