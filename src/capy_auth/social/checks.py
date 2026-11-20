"""Django system checks for social sign-in: allauth's social app and capy-auth's adapter
must be in use (or the admin's Sign-in providers page does nothing, and providers stored
in the database would be offered), and allauth's pretend provider never runs with DEBUG
off. Nothing here imports allauth's social code before checking the app is
installed: without it, that import would crash before the check could say what to do."""

from django.apps import apps
from django.conf import settings
from django.core.checks import Error, Warning
from django.utils.module_loading import import_string

SOCIAL_APP = "allauth.socialaccount"
ADAPTER_PATH = "capy_auth.social.adapter.SocialAccountAdapter"
PRETEND_PROVIDER = "allauth.socialaccount.providers.dummy"
ALLAUTH_ADAPTER = "allauth.socialaccount.adapter.DefaultSocialAccountAdapter"
STARTING_SETTING = "CAPY_AUTH_SOCIAL_PROVIDERS_ON"


def uses_capy_auth_adapter():
    from .adapter import SocialAccountAdapter  # allauth's social app is installed by now

    path = getattr(settings, "SOCIALACCOUNT_ADAPTER", ALLAUTH_ADAPTER)
    try:
        adapter = import_string(path)
    except ImportError:
        return False
    return isinstance(adapter, type) and issubclass(adapter, SocialAccountAdapter)


def check_social_setup(app_configs, **kwargs):
    if apps.is_installed(SOCIAL_APP) and uses_capy_auth_adapter():
        return []
    return [
        Error(
            "capy-auth's social sign-in needs allauth's social app and capy-auth's social "
            "adapter, which offers only the providers switched on on the admin's Sign-in "
            "providers page. Every project needs both, even with no providers set up.",
            hint=f'Add "{SOCIAL_APP}" to INSTALLED_APPS and set SOCIALACCOUNT_ADAPTER = '
            f'"{ADAPTER_PATH}" (or a subclass of it), as capy-auth\'s README says.',
            id="capy_auth.E013",
        )
    ]


def check_pretend_provider(app_configs, **kwargs):
    """allauth's pretend provider signs anyone in as any email they type: development
    only. Looks at the providers allauth loaded, so any way of installing it (or a copy
    of it) counts; capy-auth's adapter also refuses it at run time with DEBUG off."""
    if settings.DEBUG or not apps.is_installed(SOCIAL_APP):
        return []
    from allauth.socialaccount.providers import registry

    from .selectors import is_pretend

    if not any(is_pretend(cls) for cls in registry.get_class_list()):
        return []
    return [
        Error(
            "allauth's pretend sign-in provider is installed while DEBUG is off (as in "
            "production and tests): anyone could sign in as any email address with it.",
            hint=f'Add "{PRETEND_PROVIDER}" to INSTALLED_APPS only when DEBUG is on (in '
            "development), as capy-auth's README says.",
            id="capy_auth.E014",
        )
    ]


def check_starting_providers(app_configs, **kwargs):
    """CAPY_AUTH_SOCIAL_PROVIDERS_ON must be a list of ids; one that isn't set up does
    nothing, which is usually a typo."""
    value = getattr(settings, STARTING_SETTING, [])
    if not isinstance(value, list | tuple) or not all(isinstance(i, str) for i in value):
        return [
            Error(
                f"{STARTING_SETTING} must be a list of provider ids, not {value!r}.",
                hint="When it comes from the environment, read it as a list "
                f'(env.list("{STARTING_SETTING}", default=[])).',
                id="capy_auth.E015",
            )
        ]
    if not apps.is_installed(SOCIAL_APP):
        return []  # E013 reports it
    from .services import set_up_provider_ids

    unknown = sorted(set(value) - set_up_provider_ids())
    if not unknown:
        return []
    return [
        Warning(
            f"{STARTING_SETTING} names providers that aren't set up: {', '.join(unknown)}.",
            hint='Use the ids the admin\'s Sign-in providers page shows ("github", or an '
            "OpenID Connect server's provider_id), and give each its client ID and "
            "secret in SOCIALACCOUNT_PROVIDERS.",
            id="capy_auth.W007",
        )
    ]
