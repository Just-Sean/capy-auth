"""Changes to stored MFA data: re-encrypting every secret with the first key (to finish
changing keys), and warning a person whose code step keeps failing."""

from allauth.account.adapter import get_adapter
from allauth.account.utils import user_email
from allauth.mfa.models import Authenticator
from cryptography.fernet import InvalidToken
from django.core.cache import cache
from django.db import transaction

from . import crypto

# Where each kind of authenticator keeps encrypted values (allauth 65.22.1: the TOTP
# secret, the recovery codes' seed, and codes migrated from older allauth versions).
ENCRYPTED_FIELDS = {"totp": ["secret"], "recovery_codes": ["seed"]}
MIGRATED_CODES = "migrated_codes"

FAILURES_TO_WARN = 5
FAILURE_WINDOW_SECONDS = 60 * 60
FAILURES_KEY = "capy_auth:mfa-failures:{}"
FAILED_CODES_NOTICE = "capy_auth/email/mfa_codes_failed"


def reencrypt_all():
    """Re-encrypts every stored MFA secret with the first key, so older keys can be
    dropped. Returns (how many authenticators were done, how many couldn't be read)."""
    done = unreadable = 0
    for pk in Authenticator.objects.values_list("pk", flat=True).iterator():
        with transaction.atomic():  # one at a time, so no long lock
            authenticator = Authenticator.objects.select_for_update().get(pk=pk)
            try:
                authenticator.data = reencrypted(authenticator.type, authenticator.data)
            except InvalidToken:
                unreadable += 1
                continue
            authenticator.save(update_fields=["data"])
            done += 1
    return done, unreadable


def reencrypted(kind, data):
    data = dict(data)
    for field in ENCRYPTED_FIELDS.get(kind, []):
        if field in data:
            data[field] = crypto.reencrypt(data[field])
    if kind == "recovery_codes" and data.get(MIGRATED_CODES):
        data[MIGRATED_CODES] = [crypto.reencrypt(code) for code in data[MIGRATED_CODES]]
    return data


def count_failed_code(user):
    """A wrong code at the code step: after FAILURES_TO_WARN in an hour, email the
    owner once (someone has their password). The count lives in the cache."""
    key = FAILURES_KEY.format(user.pk)
    cache.add(key, 0, FAILURE_WINDOW_SECONDS)
    if cache.incr(key) == FAILURES_TO_WARN and (email := user_email(user)):
        get_adapter().send_mail(FAILED_CODES_NOTICE, email, {"user": user})


def forget_failed_codes(user):
    cache.delete(FAILURES_KEY.format(user.pk))
