"""Refuses new passwords that appear in Have I Been Pwned's list of breached passwords
(NIST SP 800-63B). The service only sees the first 5 characters of the password's SHA-1
hash, a prefix shared by hundreds of hashes, and padding hides even that from anyone
watching the traffic. When the check applies and the service can't be reached, or its
answer isn't understood, the password is refused (it fails closed); after a failure, the
next minute's passwords are refused at once instead of each waiting on the service."""

import hashlib
import logging
import re
import time
from http import HTTPStatus
from http.client import HTTPException, HTTPSConnection

from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _
from django.views.decorators.debug import sensitive_variables

from capy_auth.config.models import BreachedPasswordCheck
from capy_auth.config.selectors import get_auth_settings

logger = logging.getLogger("capy_auth")

HIBP_HOST = "api.pwnedpasswords.com"
USER_AGENT = "capy-auth breached-password check"
# The whole call has 3 seconds (a slow service mustn't leave people on a stuck page).
TOTAL_SECONDS = 3
READ_BYTES = 64 * 1024
MAX_ANSWER_BYTES = 1_000_000  # a padded answer is about 40 KB
# A padded answer has hundreds of lines; far fewer means something is wrong.
MIN_ANSWER_LINES = 100
ANSWER_LINE = re.compile(r"([0-9A-F]{35}):(\d+)")
# After the service fails, refuse at once for this long instead of asking it again.
DOWN_KEY = "capy_auth:breach-check-down"
DOWN_SECONDS = 60


class ServiceUnavailable(Exception):
    """Have I Been Pwned couldn't be asked, or its answer wasn't understood."""


def fetch_range(prefix):
    """HIBP's answer for one 5-character hash prefix: lines of "SUFFIX:COUNT"."""
    deadline = time.monotonic() + TOTAL_SECONDS
    connection = HTTPSConnection(HIBP_HOST, timeout=TOTAL_SECONDS)  # verifies TLS
    try:
        connection.request(
            "GET", f"/range/{prefix}", headers={"Add-Padding": "true", "User-Agent": USER_AGENT}
        )
        response = connection.getresponse()
        if response.status != HTTPStatus.OK:
            raise ServiceUnavailable(f"HTTP {response.status}")
        return read_before(response, deadline).decode("ascii")
    except (OSError, HTTPException, UnicodeDecodeError) as error:
        raise ServiceUnavailable(type(error).__name__) from None
    finally:
        connection.close()


def read_before(response, deadline):
    """The answer's body, if it all arrives in time and isn't far too big."""
    body = b""
    while True:
        if time.monotonic() > deadline:
            raise ServiceUnavailable("answer too slow")
        chunk = response.read(READ_BYTES)
        if not chunk:
            return body
        body += chunk
        if len(body) > MAX_ANSWER_BYTES:
            raise ServiceUnavailable("answer too large")


@sensitive_variables("password", "digest", "suffix")
def times_breached(password):
    """How many times the password appears in known breaches (0 if never)."""
    digest = hashlib.sha1(password.encode("utf-8", "surrogatepass"), usedforsecurity=False)
    digest = digest.hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    lines = [line.strip().upper() for line in fetch_range(prefix).splitlines() if line.strip()]
    if len(lines) < MIN_ANSWER_LINES:
        raise ServiceUnavailable("answer too short")
    for line in lines:
        match = ANSWER_LINE.fullmatch(line)
        if match is None:
            raise ServiceUnavailable("answer not understood")
        if match[1] == suffix:
            return int(match[2])  # padding lines have a count of 0
    return 0


@sensitive_variables("password")
def ask_service(password):
    """times_breached(), but refusing at once while the service recently failed."""
    if remembered_down():
        raise ServiceUnavailable("recently unreachable")
    try:
        return times_breached(password)
    except ServiceUnavailable as problem:
        logger.error(
            "Have I Been Pwned couldn't be reached or answered badly (%s); new passwords "
            "are refused for the next %s seconds.",
            problem,
            DOWN_SECONDS,
        )
        remember_down()
        raise


def remembered_down():
    try:
        return bool(cache.get(DOWN_KEY))
    except Exception:  # the cache being down only means asking the service again
        return False


def remember_down():
    try:
        cache.set(DOWN_KEY, True, DOWN_SECONDS)
    except Exception:  # the cache being down only means asking the service again
        return


def level():
    return get_auth_settings().breached_password_check


def is_checked(user):
    """Whether this person's new password is checked, by the settings page's level."""
    if level() == BreachedPasswordCheck.EVERYONE:
        return True
    is_staff = bool(getattr(user, "is_staff", False) or getattr(user, "is_superuser", False))
    return level() == BreachedPasswordCheck.STAFF and is_staff


class BreachedPasswordValidator:
    """Add to AUTH_PASSWORD_VALIDATORS (see the README)."""

    @sensitive_variables("password")
    def validate(self, password, user=None):
        if not is_checked(user):
            return
        try:
            breaches = ask_service(password)
        except ServiceUnavailable:
            raise ValidationError(
                _(
                    "We can’t check this password against known data breaches right now. "
                    "Please try again in a few minutes. If this keeps happening, contact "
                    "the site’s support."
                ),
                code="breached_check_unavailable",
            ) from None
        if breaches:
            raise ValidationError(
                _(
                    "This password has appeared in a data breach, so it isn’t safe to use. "
                    "Please choose a different one. If you use it anywhere else, change it "
                    "there too."
                ),
                code="password_breached",
            )

    def get_help_text(self):
        """Only where the check applies to everyone; staff are told on their own forms
        by the error, and an empty text is left out of the list (fields.html)."""
        if level() == BreachedPasswordCheck.EVERYONE:
            return _("Your password can’t be one that has appeared in a data breach.")
        return ""
