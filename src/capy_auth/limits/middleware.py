"""When the cache (Redis) is down, allauth can't count attempts, so its pages fail. This
turns that failure into a proper "temporarily unavailable" page inside the layout, with
status 503, instead of a server error. Nothing gets through: the limits are never
skipped. It does the same when a stored MFA secret can't be decrypted. A project adds it
to MIDDLEWARE (see the README)."""

import logging

from django.core.cache import cache
from django.core.exceptions import PermissionDenied
from django.http import Http404
from django.shortcuts import render

from capy_auth.mfa.crypto import SecretUnreadable

logger = logging.getLogger("capy_auth")

# Names of the pages this covers: allauth's account, two-step sign-in (including passkey
# sign-in) and sessions pages, and capy-auth's own.
ACCOUNT_PAGE_PREFIXES = ("account_", "mfa_", "usersessions_", "capy_auth_")
# Cache client libraries whose own errors mean the cache is down.
CACHE_CLIENT_MODULES = ("redis", "pymemcache", "pylibmc")
PROBE_KEY = "capy_auth:cache-probe"
RETRY_AFTER_SECONDS = 60


def is_account_page(request):
    match = request.resolver_match
    return bool(match and match.url_name and match.url_name.startswith(ACCOUNT_PAGE_PREFIXES))


def raised_by_cache(exception):
    """Whether the error itself shows the cache is down (no second call needed, which
    would wait for the cache's timeout again)."""
    if isinstance(exception, ConnectionError | TimeoutError):
        return True
    return type(exception).__module__.split(".")[0] in CACHE_CLIENT_MODULES


def cache_is_down():
    """Writes and reads a probe, since a cache can answer reads but refuse writes (out
    of memory, a read-only copy)."""
    try:
        cache.set(PROBE_KEY, True, 1)
        cache.get(PROBE_KEY)
    except Exception:  # whatever the cache backend raises when it's down
        return True
    return False


class CacheDownMiddleware:
    """Acts only after a view has failed, so it can never let a request skip allauth's
    checks; it only changes which error page people see."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_exception(self, request, exception):
        """Only for account pages, and only when the cache is down; a missing page, a
        refusal or any other error is left to Django as usual. Also, on any page, a
        stored MFA secret that can't be decrypted (the key is gone: mfa/crypto.py, which
        logs it) gets a page saying what to do instead of a crash; nobody gets in."""
        if isinstance(exception, SecretUnreadable):
            return render(request, "capy_auth/mfa_unavailable.html", status=503)
        if not is_account_page(request) or isinstance(exception, Http404 | PermissionDenied):
            return None
        if not (raised_by_cache(exception) or cache_is_down()):
            return None
        logger.error(
            "The cache is unavailable, so account pages are closed until it's back.",
            exc_info=exception,
        )
        response = render(request, "capy_auth/unavailable.html", status=503)
        response["Retry-After"] = str(RETRY_AFTER_SECONDS)
        return response
