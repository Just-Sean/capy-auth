"""URLs for the stand-in project, plus pages the tests use: one in the layout, and
another app's login page (Django's own login, not allauth's)."""

from allauth.account.decorators import secure_admin_login
from django.contrib import admin, messages
from django.contrib.auth import authenticate, login
from django.http import HttpResponse
from django.shortcuts import render
from django.urls import include, path


def layout_check(request):
    """A page like the module's own: it extends layout.html and adds a message."""
    messages.success(request, "Saved <b>ok</b>")
    return render(request, "layout_check.html")


def other_apps_login(request):
    """Another app's login page: Django's own authenticate() and login(), not allauth's."""
    user = authenticate(request, email=request.POST["email"], password=request.POST["password"])
    login(request, user)
    return HttpResponse(status=204)


# As the README tells a project: the admin's login goes through allauth's sign-in page.
admin.site.login = secure_admin_login(admin.site.login)

urlpatterns = [
    path("admin/", admin.site.urls),
    path("layout-check/", layout_check),
    path("other-apps-login/", other_apps_login),
    path("accounts/", include("capy_auth.urls")),
]
