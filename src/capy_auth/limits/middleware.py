"""When the cache (Redis) is down, allauth can't count attempts, so its pages fail. This
turns that failure into a proper "temporarily unavailable" page inside the layout, with
status 503, instead of a server error. Nothing gets through: the limits are never
skipped. A project adds it to MIDDLEWARE (see the README)."""

import logging

from django.core.cache import cache
from django.shortcuts import render

logger = logging.getLogger("capy_auth")

# Names of the pages this covers: allauth's account pages and capy-auth's own.
ACCOUNT_PAGE_PREFIXES = ("account_", "capy_auth_")
PROBE_KEY = "capy_auth:cache-probe"
RETRY_AFTER_SECONDS = 60


def is_account_page(request):
    match = getattr(request, "resolver_match", None)
    return bool(match and match.url_name and match.url_name.startswith(ACCOUNT_PAGE_PREFIXES))


def cache_is_down():
    try:
        cache.get(PROBE_KEY)
    except Exception:  # whatever the cache backend raises when it's down
        return True
    return False


class CacheDownMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_exception(self, request, exception):
        """Only for account pages, and only when the cache really is down; any other
        error is left to Django as usual."""
        if not is_account_page(request) or not cache_is_down():
            return None
        logger.error(
            "The cache is unavailable, so sign-in pages are closed until it's back (%s).",
            type(exception).__name__,
        )
        response = render(request, "capy_auth/unavailable.html", status=503)
        response["Retry-After"] = str(RETRY_AFTER_SECONDS)
        return response
