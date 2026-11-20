"""The Sign-in providers page in the Django admin: each set-up provider, whether its
credentials are set, the callback address to register with the provider, and its
switch (on its own page, where the switch is labelled). The secrets themselves stay in
the environment and never show here. allauth's own "Social applications" page, which
stores secrets in the database, is removed."""

from importlib import import_module

from allauth.socialaccount.models import SocialApp
from allauth.socialaccount.providers import registry
from django.contrib import admin, messages
from django.urls import NoReverseMatch, reverse
from django.utils.translation import gettext_lazy as _

from .models import SocialProvider
from .services import set_up_providers

NOT_SET_UP = _(
    "Not set up: whoever runs the site adds its client ID and secret to the settings "
    "(capy-auth's README, “Sign-in providers”). Delete this row if it was "
    "removed on purpose."
)
STORED_SECRETS = _(
    "allauth's database table of sign-in providers has rows, so client secrets are "
    "stored in the database. capy-auth never uses them: move each provider's client ID "
    "and secret to the settings, then delete the rows (capy-auth's README, "
    "“Sign-in providers”)."
)
NONE = "—"


def remove_allauths_secret_page(site):
    """allauth registers its page when its admin module loads, which may be after this
    one: load it now, so the page is there to remove (unless the project already did)."""
    import_module("allauth.socialaccount.admin")
    if site.is_registered(SocialApp):
        site.unregister(SocialApp)


remove_allauths_secret_page(admin.site)


def callback_path(provider_id):
    """Where the provider sends people back: allauth's address for that provider, or
    for an OpenID Connect server set up in the settings, its own under oidc/. None for
    one with no such address (SAML, allauth's pretend provider)."""
    if registry.get_class(provider_id):
        name, kwargs = f"{provider_id}_callback", {}
    else:
        name, kwargs = "openid_connect_callback", {"provider_id": provider_id}
    try:
        return reverse(name, kwargs=kwargs)
    except NoReverseMatch:
        return None


@admin.register(SocialProvider)
class SocialProviderAdmin(admin.ModelAdmin):
    list_display = ["provider_id", "name", "enabled", "status", "callback"]
    fields = ["provider_id", "name", "status", "callback", "enabled"]
    readonly_fields = ["provider_id", "name", "status", "callback"]
    actions = None  # its only action, bulk delete, would delete set-up ones too

    def is_set_up(self, obj):
        return obj.provider_id in set_up_providers()

    @admin.display(description=_("name"))
    def name(self, obj):
        return set_up_providers().get(obj.provider_id) or NONE

    @admin.display(description=_("set up"))
    def status(self, obj):
        return _("Set up") if self.is_set_up(obj) else NOT_SET_UP

    @admin.display(description=_("callback (add it after the site's address)"))
    def callback(self, obj):
        return (self.is_set_up(obj) and callback_path(obj.provider_id)) or NONE

    def get_readonly_fields(self, request, obj=None):
        """A provider that isn't set up can't be switched on: it would do nothing."""
        if obj is not None and not self.is_set_up(obj):
            return [*self.readonly_fields, "enabled"]
        return self.readonly_fields

    def has_add_permission(self, request):
        return False  # rows come from the settings, after each migrate

    def has_delete_permission(self, request, obj=None):
        """Only rows of providers no longer set up: a set-up one would come back at the
        next deploy's migrate. Switching it off is how to stop offering it."""
        allowed = super().has_delete_permission(request, obj)
        return allowed and (obj is None or not self.is_set_up(obj))

    def changelist_view(self, request, extra_context=None):
        if SocialApp.objects.exists():
            messages.warning(request, STORED_SECRETS)
        return super().changelist_view(request, extra_context)
