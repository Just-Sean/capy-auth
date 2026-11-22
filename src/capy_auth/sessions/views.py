"""allauth's "Signed-in devices" page, recording the current session first when nobody
did (a session started before allauth's user sessions were installed), so this device
is always listed and the page's button does what it says."""

from allauth.usersessions.views import ListUserSessionsView

from .recording import record_session


class SessionsView(ListUserSessionsView):
    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            record_session(request, request.user)
        return super().dispatch(request, *args, **kwargs)


sessions_page = SessionsView.as_view()
