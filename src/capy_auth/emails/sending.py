"""Keeps a finished email in the cache until the background job sends it, so the job
carries only a random key: verification codes and reset links never go into the job or
the database."""

import secrets

from django.core.cache import cache
from django.core.mail import EmailMultiAlternatives

CACHE_KEY_PREFIX = "capy_auth:email:"
# How long a queued email waits for the worker. A code or reset link in an email that
# waits longer would have run out anyway.
WAIT_SECONDS = 60 * 60


def as_data(message):
    """The parts of an email, as plain data the cache can keep."""
    return {
        "subject": message.subject,
        "body": message.body,
        "from_email": message.from_email,
        "to": list(message.to),
        "alternatives": [
            [content, mimetype] for content, mimetype in getattr(message, "alternatives", [])
        ],
    }


def from_data(data):
    """The email again, from as_data()."""
    message = EmailMultiAlternatives(data["subject"], data["body"], data["from_email"], data["to"])
    for content, mimetype in data["alternatives"]:
        message.attach_alternative(content, mimetype)
    return message


def store(message):
    """Keeps the email in the cache and returns its random key. Raises whatever the
    cache raises when it's down."""
    key = secrets.token_urlsafe(32)
    cache.set(CACHE_KEY_PREFIX + key, as_data(message), WAIT_SECONDS)
    return key


def take(key):
    """The email kept under the key, removed from the cache so it's sent only once; None
    when it has expired."""
    data = cache.get(CACHE_KEY_PREFIX + key)
    cache.delete(CACHE_KEY_PREFIX + key)
    return None if data is None else from_data(data)
