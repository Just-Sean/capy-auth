"""The ban list's pages in the Django admin. Banning or unbanning changes accounts, so
these pages also need permission to change accounts."""

from django.contrib import admin
from django.contrib.auth import get_permission_codename, get_user_model
from django.utils.translation import gettext_lazy as _
from django.utils.translation import ngettext

from .models import BannedEmail, BannedEmailAttempt, BannedSocialAccount
from .services import lift_bans, suspend_accounts


def can_change_accounts(request):
    options = get_user_model()._meta
    return request.user.has_perm(
        f"{options.app_label}.{get_permission_codename('change', options)}"
    )


class BanAdmin(admin.ModelAdmin):
    def has_add_permission(self, request):
        return super().has_add_permission(request) and can_change_accounts(request)

    def has_change_permission(self, request, obj=None):
        return super().has_change_permission(request, obj) and can_change_accounts(request)

    def has_delete_permission(self, request, obj=None):
        return super().has_delete_permission(request, obj) and can_change_accounts(request)


@admin.register(BannedEmail)
class BannedEmailAdmin(BanAdmin):
    list_display = ["email", "created_at"]
    search_fields = ["email"]
    readonly_fields = ["created_at", "suspended"]
    actions = ["lift_and_reactivate"]

    @admin.display(description=_("accounts it suspended"))
    def suspended(self, ban):
        return ", ".join(str(account) for account in ban.suspended_accounts.all()) or "—"

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        count = suspend_accounts(obj)
        if count:
            self.message_user(
                request,
                ngettext(
                    "%(count)d account using this address was suspended and emailed.",
                    "%(count)d accounts using this address were suspended and emailed.",
                    count,
                )
                % {"count": count},
            )

    @admin.action(
        description=_("Lift the selected bans and reactivate the accounts they suspended"),
        permissions=["delete"],
    )
    def lift_and_reactivate(self, request, queryset):
        count = lift_bans(queryset)
        self.message_user(
            request,
            ngettext(
                "Bans lifted; %(count)d account was reactivated.",
                "Bans lifted; %(count)d accounts were reactivated.",
                count,
            )
            % {"count": count},
        )


@admin.register(BannedSocialAccount)
class BannedSocialAccountAdmin(BanAdmin):
    list_display = ["provider", "uid", "created_at"]
    list_filter = ["provider"]
    search_fields = ["uid"]
    readonly_fields = ["created_at"]


@admin.register(BannedEmailAttempt)
class BannedEmailAttemptAdmin(admin.ModelAdmin):
    """A read-only record: staff look and decide, and may delete old entries."""

    list_display = ["created_at", "kind", "email", "account", "ip_address"]
    list_filter = ["kind"]
    search_fields = ["email"]
    list_select_related = ["account"]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
