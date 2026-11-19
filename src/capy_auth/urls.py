"""capy-auth's URLs: its own pages plus allauth's. A project mounts them at accounts/
(see the README). They have no app_name namespace, unlike other modules' URLs:
allauth's pages keep their own names (account_login, account_signup, …), which
allauth's code and templates rely on, so capy-auth's own names start with capy_auth_
instead."""

from django.urls import include, path

from capy_auth.account.views import account_page

urlpatterns = [
    # Django's default LOGIN_REDIRECT_URL, so people land here after logging in.
    path("profile/", account_page, name="capy_auth_account"),
    path("", include("allauth.urls")),
]
