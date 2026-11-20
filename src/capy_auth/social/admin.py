"""The sign-in providers' page in the Django admin: switch each set-up provider on or
off, see whether its credentials are set, and copy the callback address to register
with the provider. The secrets themselves stay in the environment and never show here.
allauth's own "Social applications" page, which stores secrets in the database, is
removed."""

from importlib import import_module

from allauth.socialaccount.models import SocialApp
from allauth.socialaccount.providers import registry
from django.contrib import admin
from django.urls import NoReverseMatch, reverse
from django.utils.translation import gettext_lazy as _

from .models import SocialProvider
from .services import set_up_provider_ids

# allauth registers its page when its admin module loads, which may be after this one:
# load it now, so the page is there to remove.
import_module("allauth.socialaccount.admin")
admin.site.unregister(SocialApp)

NOT_SET_UP = _("Not set up: its client ID and secret aren't in the settings")
NO_CALLBACK = "—"


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
    list_editable = ["enabled"]
    fields = ["provider_id", "enabled"]
    readonly_fields = ["provider_id"]

    @admin.display(description=_("name"))
    def name(self, obj):
        provider_class = registry.get_class(obj.provider_id)
        return provider_class.name if provider_class else _("OpenID Connect")

    @admin.display(description=_("set up"))
    def status(self, obj):
        return _("Set up") if obj.provider_id in set_up_provider_ids() else NOT_SET_UP

    @admin.display(
        description=_("callback (register it with the provider, after the site's address)")
    )
    def callback(self, obj):
        return callback_path(obj.provider_id) or NO_CALLBACK

    def has_add_permission(self, request):
        return False  # rows come from the settings, after each migrate
