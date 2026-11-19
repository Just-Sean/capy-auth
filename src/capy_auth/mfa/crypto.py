"""Encrypting the secrets allauth's MFA stores (authenticator-app keys, the seed of
recovery codes), so a copy of the database alone doesn't give them away. Fernet, from
the cryptography library: AES encryption with a tamper check.

The keys come from the project's CAPY_AUTH_ENCRYPTION_KEYS setting, a list (or one
comma-separated value) read from the environment: the first key encrypts, every key
decrypts. To change keys: put the new one first, run `manage.py capy_auth_reencrypt`
(which re-encrypts every stored secret with it), then drop the old one. In development
(DEBUG on) without a key, a stand-in made from SECRET_KEY is used, and Django's checks
say so; in production the site doesn't start without one (mfa/checks.py).

The keys never appear in error reports: every function that holds one hides its local
variables (sensitive_variables)."""

import base64
import hashlib
import logging

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from django.conf import settings
from django.views.decorators.debug import sensitive_variables

logger = logging.getLogger("capy_auth")

SETTING = "CAPY_AUTH_ENCRYPTION_KEYS"
GENERATE_SNIPPET = (
    'python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
)
GENERATE_COMMANDS = (
    f"uv run {GENERATE_SNIPPET}   (development)\n"
    "docker compose -f compose.yaml -f compose.prod.yaml run --rm --no-deps web "
    f"{GENERATE_SNIPPET}   (production)"
)


class KeyProblem(ValueError):
    """CAPY_AUTH_ENCRYPTION_KEYS is missing or holds something that isn't a key."""


class SecretUnreadable(Exception):
    """A stored MFA secret can't be decrypted with any of the keys: the key that
    encrypted it is gone, or it wasn't stored by capy-auth (a project that used
    allauth's MFA before installing capy-auth stored its secrets unencrypted)."""


@sensitive_variables()
def configured_keys():
    """The keys from the setting, in order, without empty entries. Raises KeyProblem
    when one isn't a key (naming its position, never its value)."""
    keys = getattr(settings, SETTING, None) or []
    if isinstance(keys, str):
        keys = keys.split(",")
    keys = [key.strip() for key in keys if key and key.strip()]
    for position, key in enumerate(keys, start=1):
        try:
            Fernet(key)
        except (ValueError, TypeError) as error:
            raise KeyProblem(f"key {position} of {SETTING} isn't a valid key") from error
    return keys


@sensitive_variables()
def stand_in_key():
    """A development-only key, made from SECRET_KEY so every project's differs."""
    digest = hashlib.sha256(b"capy-auth development key:" + settings.SECRET_KEY.encode())
    return base64.urlsafe_b64encode(digest.digest()).decode()


@sensitive_variables()
def keys_in_use():
    keys = configured_keys()
    if keys:
        return keys
    if settings.DEBUG:
        return [stand_in_key()]
    raise KeyProblem(f"{SETTING} isn't set")


@sensitive_variables()
def fernet():
    return MultiFernet([Fernet(key) for key in keys_in_use()])


@sensitive_variables()
def encrypt(text):
    return fernet().encrypt(text.encode()).decode()


@sensitive_variables()
def decrypt(token):
    """Raises SecretUnreadable (logged as an error naming the setting) when no key can
    decrypt it; capy-auth's middleware then shows a clear page instead of a crash."""
    try:
        return fernet().decrypt(token.encode()).decode()
    except InvalidToken as error:
        logger.error(
            "A stored MFA secret can't be decrypted with any key in %s: the key that "
            "encrypted it is gone, or it wasn't stored by capy-auth. Staff can let the "
            "person back in by removing their authenticators in the admin.",
            SETTING,
        )
        raise SecretUnreadable from error


@sensitive_variables()
def reencrypt(token):
    """The same secret encrypted with the first key. Raises InvalidToken when no key
    can read it."""
    return fernet().rotate(token.encode()).decode()
