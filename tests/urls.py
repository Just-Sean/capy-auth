"""URLs for the stand-in project, plus a page the stand-in project's own tests use."""

from django.contrib import admin, messages
from django.shortcuts import render
from django.urls import path


def layout_check(request):
    """A page like the module's own: it extends layout.html and adds a message."""
    messages.success(request, "Saved <b>ok</b>")
    return render(request, "layout_check.html")


urlpatterns = [
    path("admin/", admin.site.urls),
    path("layout-check/", layout_check),
]
