"""Recording sign-ins for the "Signed-in devices" page. allauth records only sign-ins
through its own pages; capy-auth also records Django's own logins (the admin's login
page, or any code calling django.contrib.auth.login) and, when someone opens the page
from a session nobody recorded, that session. Otherwise those sessions would be missing
from the page and survive "Sign out everywhere else"."""

import logging

from allauth.usersessions.models import UserSession
from django.core.exceptions import ImproperlyConfigured, PermissionDenied

logger = logging.getLogger("capy_auth")


def record_session(request, user):
    """Records the signed-in session unless it's already recorded. Never stops a sign-in:
    when allauth can't read the visitor's address, it's left unrecorded (logged)."""
    session_key = request.session.session_key
    if session_key and UserSession.objects.filter(session_key=session_key).exists():
        return
    try:
        UserSession.objects.create_from_request(request, user=user)
    except PermissionDenied, ImproperlyConfigured:
        logger.warning("A sign-in wasn't recorded: the visitor's address couldn't be read.")


def record_django_login(sender, request, user, **kwargs):
    """Django's user_logged_in signal (not allauth's): every login, the admin's too."""
    if request is not None and hasattr(request, "session"):
        record_session(request, user)
