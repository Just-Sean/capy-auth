"""Django system check: capy-auth can't work without email (signup codes, password
resets), so a production site whose email can't be sent is stopped at startup."""

from django.conf import settings
from django.core.checks import Error

# Backends that deliver nothing: Django's dummy one; the console and file ones, which
# also write reset links and codes where they shouldn't be; and capy-project's stand-in
# when EMAIL_URL isn't set ("Email isn't set up"). Django's in-memory one stays allowed:
# capy-project's own tests run without DEBUG and use it.
NO_EMAIL_BACKENDS = {
    "django.core.mail.backends.dummy.EmailBackend",
    "django.core.mail.backends.console.EmailBackend",
    "django.core.mail.backends.filebased.EmailBackend",
}
NOT_SET_UP_SUFFIX = ".EmailNotSetUpBackend"
SMTP_BACKEND = "django.core.mail.backends.smtp.EmailBackend"  # a mailer's default


def no_email_problem():
    """Why the default mailer can't deliver email, or None. Only Django 6.1's MAILERS
    is read (as capy-project sets it): reading the older EMAIL_BACKEND is deprecated, so
    a project still on it isn't checked."""
    if not hasattr(settings, "MAILERS"):
        return None
    mailers = settings.MAILERS
    default = mailers.get("default") if isinstance(mailers, dict) else None
    if not isinstance(default, dict):
        return "MAILERS has no default mailer"
    backend = default.get("BACKEND", SMTP_BACKEND)
    if backend in NO_EMAIL_BACKENDS or backend.endswith(NOT_SET_UP_SUFFIX):
        return f"the default mailer ({backend}) delivers nothing"
    return None


def check_email_can_be_sent(app_configs, **kwargs):
    problem = None if settings.DEBUG else no_email_problem()
    if problem is None:
        return []
    return [
        Error(
            f"capy-auth needs email (signup codes, password resets), but {problem}.",
            hint="Set up email: in a project made from capy-project, set EMAIL_URL and "
            "DJANGO_DEFAULT_FROM_EMAIL (its README's Email section).",
            id="capy_auth.E004",
        )
    ]
