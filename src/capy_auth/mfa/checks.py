"""Django system checks for MFA: allauth's MFA app and capy-auth's adapter must be in
use, or secrets would be stored readable; and the encryption key must be set up, as
whoever sets up the project is told at every step (README, development, production)."""

from django.apps import apps
from django.conf import settings
from django.core.checks import Error, Warning
from django.utils.module_loading import import_string

from .adapter import MFAAdapter
from .crypto import GENERATE_COMMAND, SETTING, KeyProblem, configured_keys

MFA_APP = "allauth.mfa"
ADAPTER_PATH = "capy_auth.mfa.adapter.MFAAdapter"
KEY_HINT = (
    f"Generate a key with: {GENERATE_COMMAND}\n"
    f"Put it in the environment as {SETTING} (in a project made from capy-project, in "
    ".env.production), and back it up with the project's other secrets, not with the "
    "database backup. See capy-auth's README, install step 4."
)


def uses_capy_auth_adapter():
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


def check_encryption_keys(app_configs, **kwargs):
    try:
        keys = configured_keys()
    except KeyProblem as problem:
        return [
            Error(
                f"capy-auth can't encrypt MFA secrets: {problem}.",
                hint=KEY_HINT,
                id="capy_auth.E007",
            )
        ]
    if keys:
        return []
    if settings.DEBUG:
        return [
            Warning(
                f"capy-auth is encrypting MFA secrets with a development-only key, since "
                f"{SETTING} isn't set. Set a real key before going to production.",
                hint=KEY_HINT,
                id="capy_auth.W005",
            )
        ]
    return [
        Error(
            f"capy-auth can't encrypt MFA secrets: {SETTING} isn't set.",
            hint=KEY_HINT,
            id="capy_auth.E007",
        )
    ]
