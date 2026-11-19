"""Encrypting the secrets allauth's MFA stores (authenticator-app keys, the seed of
recovery codes), so a copy of the database alone doesn't give them away. Fernet, from
the cryptography library: AES encryption with a tamper check.

The keys come from the project's CAPY_AUTH_ENCRYPTION_KEYS setting, a list read from
the environment: the first key encrypts, every key decrypts, so a key can be changed by
putting a new one first and keeping the old one until nothing uses it. In development
(DEBUG on) without it, a stand-in key made from SECRET_KEY is used, and Django's checks
say so; in production the site doesn't start without it (mfa/checks.py)."""

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

SETTING = "CAPY_AUTH_ENCRYPTION_KEYS"
GENERATE_COMMAND = (
    'python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
)


class KeyProblem(ValueError):
    """CAPY_AUTH_ENCRYPTION_KEYS is missing or holds something that isn't a key."""


def configured_keys():
    """The keys from the setting, in order. Raises KeyProblem when one isn't a key."""
    keys = getattr(settings, SETTING, None) or []
    if isinstance(keys, str):
        keys = [key.strip() for key in keys.split(",") if key.strip()]
    for position, key in enumerate(keys, start=1):
        try:
            Fernet(key)
        except (ValueError, TypeError) as error:
            raise KeyProblem(f"key {position} of {SETTING} isn't a valid key") from error
    return list(keys)


def stand_in_key():
    """A development-only key, made from SECRET_KEY so every project's differs."""
    digest = hashlib.sha256(b"capy-auth development key:" + settings.SECRET_KEY.encode())
    return base64.urlsafe_b64encode(digest.digest()).decode()


def keys_in_use():
    keys = configured_keys()
    if keys:
        return keys
    if settings.DEBUG:
        return [stand_in_key()]
    raise KeyProblem(f"{SETTING} isn't set")


def encrypt(text):
    return MultiFernet([Fernet(key) for key in keys_in_use()]).encrypt(text.encode()).decode()


def decrypt(token):
    """Raises ImproperlyConfigured when no key in the list can decrypt it: the key that
    encrypted it was removed or lost, so the person has to set up MFA again."""
    try:
        return MultiFernet([Fernet(key) for key in keys_in_use()]).decrypt(token.encode()).decode()
    except InvalidToken as error:
        raise ImproperlyConfigured(
            f"A stored MFA secret can't be decrypted with any key in {SETTING}: the key "
            "that encrypted it isn't in the list any more."
        ) from error
