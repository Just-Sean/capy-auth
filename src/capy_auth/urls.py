"""capy-auth's URLs: its own pages plus allauth's. A project mounts them at accounts/
(see the README). They have no app_name namespace, unlike other modules' URLs:
allauth's pages keep their own names (account_login, account_signup, …), which
allauth's code and templates rely on, so capy-auth's own names start with capy_auth_
instead."""

from django.contrib.auth.decorators import login_required
from django.urls import include, path
from django.views.generic import TemplateView

# Where people land after logging in (Django's default LOGIN_REDIRECT_URL).
account_page = login_required(TemplateView.as_view(template_name="capy_auth/account.html"))

urlpatterns = [
    path("profile/", account_page, name="capy_auth_account"),
    path("", include("allauth.urls")),
]
