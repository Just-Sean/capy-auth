"""The "capy-auth settings" page in the Django admin: the one settings record, which
can be changed but not added to or deleted. The admin records each change in its
history."""

from django.contrib import admin
from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect
from django.urls import reverse

from .models import AuthSettings
from .store import get_auth_settings


@admin.register(AuthSettings)
class AuthSettingsAdmin(admin.ModelAdmin):
    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def changelist_view(self, request, extra_context=None):
        """There's only one record, so the list opens it straight away."""
        if not self.has_view_or_change_permission(request):
            raise PermissionDenied
        record = get_auth_settings()
        return redirect(reverse("admin:capy_auth_authsettings_change", args=[record.pk]))
