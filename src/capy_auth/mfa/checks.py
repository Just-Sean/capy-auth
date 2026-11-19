"""Django system checks for MFA: allauth's MFA app and capy-auth's adapter must be in
use, or secrets would be stored readable; and the encryption key must be set up, as
whoever sets up the project is told at every step (README, development, production).
Nothing here imports allauth's MFA code before checking the app is installed: without
it, that import would crash before the check could say what to do."""

from django.apps import apps
from django.conf import settings
from django.core.checks import Error, Warning
from django.utils.module_loading import import_string

from .crypto import GENERATE_COMMANDS, SETTING, KeyProblem, configured_keys, keys_in_use

MFA_APP = "allauth.mfa"
ADAPTER_PATH = "capy_auth.mfa.adapter.MFAAdapter"
KEY_HINT = (
    f"Generate a key with:\n{GENERATE_COMMANDS}\n"
    f"Put it in the environment as {SETTING} (in a project made from capy-project, in "
    ".env.production), deploy again so the site picks it up, and back it up with the "
    'project\'s other secrets, not with the database backup. See "The encryption key" '
    "in capy-auth's README."
)


def uses_capy_auth_adapter():
    from .adapter import MFAAdapter  # allauth's MFA app is installed by now

    path = getattr(settings, "MFA_ADAPTER", "allauth.mfa.adapter.DefaultMFAAdapter")
    try:
        adapter = import_string(path)
    except ImportError:
        return False
    return isinstance(adapter, type) and issubclass(adapter, MFAAdapter)


def check_mfa_setup(app_configs, **kwargs):
    if apps.is_installed(MFA_APP) and uses_capy_auth_adapter():
        return []
    return [
        Error(
            "capy-auth's two-step sign-in needs allauth's MFA app and capy-auth's MFA "
            "adapter, which encrypts the secrets it stores.",
            hint=f'Add "{MFA_APP}" to INSTALLED_APPS and set MFA_ADAPTER = '
            f'"{ADAPTER_PATH}" (or a subclass of it), as capy-auth\'s README says.',
            id="capy_auth.E008",
        )
    ]


def key_error(problem):
    return Error(
        f"capy-auth can't encrypt MFA secrets: {problem}.", hint=KEY_HINT, id="capy_auth.E007"
    )


def check_encryption_keys(app_configs, **kwargs):
    try:
        keys_in_use()
    except KeyProblem as problem:
        return [key_error(problem)]
    if configured_keys():
        return []
    return [  # keys_in_use() fell back to the development stand-in
        Warning(
            f"capy-auth is encrypting MFA secrets with a development-only key, since "
            f"{SETTING} isn't set. Set a real key before going to production.",
            hint=KEY_HINT,
            id="capy_auth.W005",
        )
    ]


def check_encryption_keys_for_deploy(app_configs, **kwargs):
    """`check --deploy` (production): a real key is needed even if DEBUG was left on,
    which would otherwise quietly use the development stand-in."""
    if not settings.DEBUG:
        return []  # check_encryption_keys already reports it
    try:
        keys = configured_keys()
    except KeyProblem:
        return []  # check_encryption_keys already reports it
    return [] if keys else [key_error(f"{SETTING} isn't set")]
