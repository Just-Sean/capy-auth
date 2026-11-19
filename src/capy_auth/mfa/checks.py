"""Django system checks for MFA: allauth's MFA app and capy-auth's adapter must be in
use, or secrets would be stored readable; the encryption key must be set up, as
whoever sets up the project is told at every step (README, development, production);
and staff must sign in with two-step sign-in, through allauth's sign-in page. Nothing
here imports allauth's MFA code before checking the app is installed: without it, that
import would crash before the check could say what to do."""

from django.apps import apps
from django.conf import settings
from django.core.checks import Error, Warning
from django.urls import NoReverseMatch, resolve, reverse
from django.utils.module_loading import import_string

from .crypto import GENERATE_COMMANDS, SETTING, KeyProblem, configured_keys, keys_in_use

MFA_APP = "allauth.mfa"
ADAPTER_PATH = "capy_auth.mfa.adapter.MFAAdapter"
INSECURE_ORIGIN = "MFA_WEBAUTHN_ALLOW_INSECURE_ORIGIN"
STAFF_MIDDLEWARE = "capy_auth.mfa.staff.StaffTwoStepMiddleware"
ACCOUNT_MIDDLEWARE = "allauth.account.middleware.AccountMiddleware"
ADMIN_LOGIN_LINE = "admin.site.login = secure_admin_login(admin.site.login)"
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


def check_passkey_origin(app_configs, **kwargs):
    """allauth's switch that lets passkeys work over plain http (for development) also
    turns off its check of where a passkey sign-in came from: never in production."""
    if settings.DEBUG or not getattr(settings, INSECURE_ORIGIN, False):
        return []
    return [
        Error(
            f"{INSECURE_ORIGIN} is on in production: allauth then doesn't check which site "
            "a passkey sign-in came from.",
            hint=f"In config/settings/users.py set {INSECURE_ORIGIN} = DEBUG (with "
            "`from .core import DEBUG` at the top), so it's on only in development; see "
            "capy-auth's README.",
            id="capy_auth.E009",
        )
    ]


def check_passkey_forms(app_configs, **kwargs):
    """capy-auth's forms for adding and renaming a passkey (mfa/forms.py): plain words,
    the "sign in without my password" box ticked, names capped. Without them the site
    still works, with allauth's wording and no limit on names."""
    if not apps.is_installed(MFA_APP):
        return []  # E008 reports it
    from .forms import FORMS  # needs allauth's MFA app

    configured = getattr(settings, "MFA_FORMS", {})
    if all(configured.get(name) == path for name, path in FORMS.items()):
        return []
    return [
        Warning(
            "capy-auth's forms for adding and renaming a passkey aren't in use, so the "
            "pages use allauth's wording and accept names of any length.",
            hint=f"Set MFA_FORMS = {FORMS!r}, as capy-auth's README says.",
            id="capy_auth.W006",
        )
    ]


def check_staff_middleware(app_configs, **kwargs):
    """Without capy-auth's middleware, staff could use the site and the admin without
    two-step sign-in (mfa/staff.py). Before allauth's middleware it can't tell who is
    signed in, and every page would fail."""
    middleware = list(settings.MIDDLEWARE)
    if STAFF_MIDDLEWARE in middleware and (
        ACCOUNT_MIDDLEWARE not in middleware
        or middleware.index(STAFF_MIDDLEWARE) > middleware.index(ACCOUNT_MIDDLEWARE)
    ):
        return []
    return [
        Error(
            "Two-step sign-in isn't required for staff: capy-auth's staff middleware "
            "isn't in MIDDLEWARE, or comes before allauth's.",
            hint=f'Put "{STAFF_MIDDLEWARE}" in MIDDLEWARE after "{ACCOUNT_MIDDLEWARE}", '
            "as capy-auth's README says.",
            id="capy_auth.E010",
        )
    ]


def check_staff_can_confirm(app_configs, **kwargs):
    """Staff confirm it's them with two-step sign-in; allauth refuses that unless "mfa"
    is one of its ways to confirm, and staff would be stuck."""
    from allauth.account import app_settings as account_settings

    if "mfa" in account_settings.REAUTHENTICATION_METHODS:
        return []
    return [
        Error(
            "Staff couldn't confirm it's them with two-step sign-in, because \"mfa\" isn't "
            "in ACCOUNT_REAUTHENTICATION_METHODS.",
            hint='Add "mfa" to ACCOUNT_REAUTHENTICATION_METHODS, or leave the setting '
            "unset (allauth's default includes it).",
            id="capy_auth.E012",
        )
    ]


def served_admin_login():
    """The view served at the admin's login address, or None without the admin's URLs."""
    try:
        return resolve(reverse("admin:login")).func
    except NoReverseMatch:
        return None


def admin_login_uses_allauth():
    """Looks at the page actually served: the line placed after urlpatterns changes the
    attribute but not the page. Each call to secure_admin_login makes a new wrapper,
    but all share one code object."""
    from allauth.account.decorators import secure_admin_login

    view = served_admin_login()
    wrapper_code = secure_admin_login(lambda request: None).__code__
    return view is None or getattr(view, "__code__", None) is wrapper_code


def check_admin_login(app_configs, **kwargs):
    """The admin's own login page skips allauth (its limits, the ban list's email, the
    second step); allauth's secure_admin_login sends it to capy-auth's sign-in page."""
    if not apps.is_installed("django.contrib.admin") or admin_login_uses_allauth():
        return []
    return [
        Error(
            "The admin's own login page is in use, so admin sign-ins skip capy-auth's "
            "sign-in page.",
            hint=f"In {settings.ROOT_URLCONF} add `from allauth.account.decorators import "
            f"secure_admin_login` and, before urlpatterns, `{ADMIN_LOGIN_LINE}`, as "
            "capy-auth's README says.",
            id="capy_auth.E011",
        )
    ]
