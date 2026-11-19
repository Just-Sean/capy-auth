"""Django system check: the "Signed-in devices" page needs allauth's user sessions app,
which records each sign-in, and its middleware."""

from django.apps import apps
from django.conf import settings
from django.core.checks import Error

SESSIONS_APP = "allauth.usersessions"
SESSIONS_MIDDLEWARE = "allauth.usersessions.middleware.UserSessionsMiddleware"


def check_user_sessions(app_configs, **kwargs):
    missing = []
    if not apps.is_installed(SESSIONS_APP):
        missing.append(f'"{SESSIONS_APP}" in INSTALLED_APPS')
    if SESSIONS_MIDDLEWARE not in settings.MIDDLEWARE:
        missing.append(f'"{SESSIONS_MIDDLEWARE}" in MIDDLEWARE')
    if not missing:
        return []
    return [
        Error(
            "capy-auth's \"Signed-in devices\" page needs allauth's user sessions, "
            f"but the project is missing {' and '.join(missing)}.",
            hint="Add them as capy-auth's README says (install step 2).",
            id="capy_auth.E006",
        )
    ]
