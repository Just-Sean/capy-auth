"""Refuses new passwords that appear in Have I Been Pwned's list of breached passwords
(NIST SP 800-63B). Only the first 5 characters of the password's SHA-1 hash leave the
server (HIBP's range API), and padding makes every answer about the same size, so
nobody watching learns anything about the password. When the check is required and the
service can't be reached, the password is refused (it fails closed)."""

import hashlib
import logging
from http.client import HTTPException, HTTPSConnection

from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

from capy_auth.config.models import BreachedPasswordCheck
from capy_auth.config.selectors import get_auth_settings

logger = logging.getLogger("capy_auth")

HIBP_HOST = "api.pwnedpasswords.com"
TIMEOUT_SECONDS = 3  # a slow service mustn't leave people waiting on a stuck page
MAX_ANSWER_BYTES = 1_000_000  # a padded answer is about 40 KB; refuse to read far more
USER_AGENT = "capy-auth breached-password check"
OK = 200


class ServiceUnavailable(Exception):
    """Have I Been Pwned couldn't be asked or didn't answer properly."""


def fetch_range(prefix):
    """HIBP's answer for one 5-character hash prefix: lines of "SUFFIX:COUNT"."""
    connection = HTTPSConnection(HIBP_HOST, timeout=TIMEOUT_SECONDS)  # verifies TLS
    try:
        connection.request(
            "GET", f"/range/{prefix}", headers={"Add-Padding": "true", "User-Agent": USER_AGENT}
        )
        response = connection.getresponse()
        if response.status != OK:
            raise ServiceUnavailable(f"HTTP {response.status}")
        return response.read(MAX_ANSWER_BYTES).decode("ascii")
    except (OSError, HTTPException, UnicodeDecodeError) as error:
        raise ServiceUnavailable(type(error).__name__) from None
    finally:
        connection.close()


def times_breached(password):
    """How many times the password appears in known breaches (0 if never)."""
    digest = hashlib.sha1(password.encode(), usedforsecurity=False).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    for line in fetch_range(prefix).splitlines():
        candidate, _colon, count = line.partition(":")
        if candidate.strip() == suffix:
            return int(count)  # padding lines have a count of 0
    return 0


def is_checked(user):
    """Whether this person's new password is checked, by the settings page's level."""
    level = get_auth_settings().breached_password_check
    if level == BreachedPasswordCheck.EVERYONE:
        return True
    is_staff = bool(getattr(user, "is_staff", False) or getattr(user, "is_superuser", False))
    return level == BreachedPasswordCheck.STAFF and is_staff


class BreachedPasswordValidator:
    """Add to AUTH_PASSWORD_VALIDATORS (see the README)."""

    def validate(self, password, user=None):
        if not is_checked(user):
            return
        try:
            breaches = times_breached(password)
        except ServiceUnavailable as problem:
            logger.error(
                "Have I Been Pwned couldn't be reached (%s), so a new password was refused.",
                problem,
            )
            raise ValidationError(
                _(
                    "We can't check your password against known data breaches right now, "
                    "so we can't save it yet. Please try again in a few minutes. If this "
                    "keeps happening, contact the site's support."
                ),
                code="breached_check_unavailable",
            ) from None
        if breaches:
            raise ValidationError(
                _(
                    "This password has appeared in a data breach, so it isn't safe to use. "
                    "Please choose a different one."
                ),
                code="password_breached",
            )

    def get_help_text(self):
        return _("Your password can't be one that has appeared in a data breach.")
