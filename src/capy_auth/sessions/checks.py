"""Django system checks for the "Signed-in devices" page: it needs allauth's user
sessions app, which records each sign-in, and its middleware, part of allauth's setup
(it tracks activity when USERSESSIONS_TRACK_ACTIVITY is on); and a session store that
can end a session on the server."""

from django.apps import apps
from django.conf import settings
from django.core.checks import Error, Warning

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


# Cookie-only sessions live in the browser, so the server can't end one.
COOKIE_SESSIONS = "django.contrib.sessions.backends.signed_cookies"


def check_session_store(app_configs, **kwargs):
    if settings.SESSION_ENGINE != COOKIE_SESSIONS:
        return []
    return [
        Warning(
            'With cookie-only sessions, "Sign out everywhere else" can\'t end other '
            "sessions: they're kept in the browsers, not on the server.",
            hint="Use a server-side SESSION_ENGINE (Django's default database sessions, "
            "as capy-project uses, or cache/cached_db).",
            id="capy_auth.W004",
        )
    ]
