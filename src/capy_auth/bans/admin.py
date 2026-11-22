"""The ban list's pages in the Django admin. Banning or unbanning changes accounts, so
these pages also need permission to change accounts (to look: to view them)."""

from django import forms
from django.contrib import admin, messages
from django.contrib.auth import get_permission_codename, get_user_model
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.utils.translation import ngettext

from .models import BannedEmail, BannedEmailAttempt, BannedSocialAccount, normalize_email
from .selectors import accounts_using
from .services import lift_bans, suspend_accounts

DELETE_OR_LIFT = _(
    "Deleting a ban keeps the accounts it suspended suspended. To reactivate them, use "
    '"Lift the selected bans and reactivate the accounts they suspended" in the list. '
    "The address can't be changed once saved: lift the ban and add a new one."
)


def has_account_permission(request, action):
    options = get_user_model()._meta
    codename = get_permission_codename(action, options)
    return request.user.has_perm(f"{options.app_label}.{codename}")


def can_see_accounts(request):
    return has_account_permission(request, "view") or has_account_permission(request, "change")


class BanAdmin(admin.ModelAdmin):
    def has_view_permission(self, request, obj=None):
        return super().has_view_permission(request, obj) and can_see_accounts(request)

    def has_add_permission(self, request):
        return super().has_add_permission(request) and has_account_permission(request, "change")

    def has_change_permission(self, request, obj=None):
        allowed = super().has_change_permission(request, obj)
        return allowed and has_account_permission(request, "change")

    def has_delete_permission(self, request, obj=None):
        allowed = super().has_delete_permission(request, obj)
        return allowed and has_account_permission(request, "change")


class BannedEmailForm(forms.ModelForm):
    request = None  # set by BannedEmailAdmin.get_form

    def clean_email(self):
        email = normalize_email(self.cleaned_data["email"])
        if accounts_using(email).filter(pk=self.request.user.pk).exists():
            raise ValidationError(
                _("This is one of your own addresses: banning it would suspend your account.")
            )
        return email


@admin.register(BannedEmail)
class BannedEmailAdmin(BanAdmin):
    form = BannedEmailForm
    list_display = ["email", "created_at"]
    search_fields = ["email"]
    fieldsets = [(None, {"fields": ["email", "reason", "created_at", "suspended"]})]
    actions = ["lift_and_reactivate"]

    @admin.display(description=_("accounts it suspended"))
    def suspended(self, ban):
        return ", ".join(str(account) for account in ban.suspended_accounts.all()) or "—"

    def get_readonly_fields(self, request, obj=None):
        return ["email", "created_at", "suspended"] if obj else ["created_at", "suspended"]

    def get_fieldsets(self, request, obj=None):
        if obj is None:
            return super().get_fieldsets(request, obj)
        return [(None, {"fields": self.fieldsets[0][1]["fields"], "description": DELETE_OR_LIFT})]

    def get_form(self, request, obj=None, **kwargs):
        form = super().get_form(request, obj, **kwargs)
        return type(form.__name__, (form,), {"request": request})

    def save_model(self, request, obj, form, change):
        """Accounts are suspended when a ban is added, not when its reason is edited
        (staff may have let one back in by hand since)."""
        super().save_model(request, obj, form, change)
        if change:
            return
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
        else:
            self.message_user(request, _("No account uses this address."), messages.INFO)

    @admin.action(
        description=_("Lift the selected bans and reactivate the accounts they suspended"),
        permissions=["delete"],
    )
    def lift_and_reactivate(self, request, queryset):
        bans = list(queryset)
        self.log_deletions(request, bans)
        accounts = lift_bans(queryset)
        for account in accounts:
            self.log_change(request, account, _("Reactivated: its ban was lifted."))
        self.message_user(
            request,
            ngettext("%(bans)d ban lifted", "%(bans)d bans lifted", len(bans)) % {"bans": len(bans)}
            + "; "
            + ngettext(
                "%(count)d account reactivated and emailed a link to choose a new password.",
                "%(count)d accounts reactivated and emailed a link to choose a new password.",
                len(accounts),
            )
            % {"count": len(accounts)},
        )


@admin.register(BannedSocialAccount)
class BannedSocialAccountAdmin(BanAdmin):
    list_display = ["provider", "uid", "created_at"]
    list_filter = ["provider"]
    search_fields = ["uid"]
    readonly_fields = ["created_at"]


@admin.register(BannedEmailAttempt)
class BannedEmailAttemptAdmin(admin.ModelAdmin):
    """A read-only record: staff look and decide, and may delete old entries. It holds
    accounts and IP addresses, so it needs the account permissions too."""

    list_display = ["created_at", "kind", "email", "account", "ip_address"]
    list_filter = ["kind"]
    search_fields = ["email"]
    list_select_related = ["account"]

    def has_view_permission(self, request, obj=None):
        return super().has_view_permission(request, obj) and can_see_accounts(request)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        allowed = super().has_delete_permission(request, obj)
        return allowed and has_account_permission(request, "change")
