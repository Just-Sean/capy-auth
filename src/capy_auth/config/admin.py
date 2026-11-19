"""The "capy-auth settings" page in the Django admin: the one settings record, which
can be changed but not added to or deleted. The admin records each change in its
history. It also shows, read-only, settings that live on the server (never their
secret values)."""

from django.contrib import admin
from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect
from django.utils.translation import gettext_lazy as _
from django.utils.translation import ngettext

from capy_auth.mfa.crypto import SETTING, KeyProblem, configured_keys

from .models import AuthSettings
from .selectors import get_auth_settings


@admin.register(AuthSettings)
class AuthSettingsAdmin(admin.ModelAdmin):
    readonly_fields = ["mfa_encryption"]

    @admin.display(description=_("MFA secrets encryption"))
    def mfa_encryption(self, record):
        """Whether the key is set up, from the server's settings; never the key."""
        try:
            keys = configured_keys()
        except KeyProblem as problem:
            return _("Not working: %(problem)s. See capy-auth's README, install step 4.") % {
                "problem": problem
            }
        if not keys:
            return _(
                "A development-only key is in use: %(setting)s isn't set. Set a real key "
                "on the server before going to production."
            ) % {"setting": SETTING}
        return ngettext(
            "Encrypted with the key in %(setting)s, kept on the server (1 key). Whoever "
            "runs the server backs it up with the project's other secrets.",
            "Encrypted with the keys in %(setting)s, kept on the server (%(count)d keys; "
            "the first encrypts). Whoever runs the server backs them up with the "
            "project's other secrets.",
            len(keys),
        ) % {"setting": SETTING, "count": len(keys)}

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def changelist_view(self, request, extra_context=None):
        """There's only one record, so the list opens it straight away."""
        if not self.has_view_or_change_permission(request):
            raise PermissionDenied
        record = get_auth_settings()
        return redirect("admin:capy_auth_authsettings_change", record.pk)
