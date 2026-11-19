"""Keeps a finished email in the cache until the background job has sent it, so the job
carries only a random key: verification codes and reset links never go into the job or
the database."""

import secrets

from django.core.cache import cache
from django.core.mail import EmailMultiAlternatives

CACHE_KEY_PREFIX = "capy_auth:email:"
SENDING_KEY_PREFIX = "capy_auth:email-sending:"
# How long a queued email waits to be sent. A code or reset link in an email that waits
# longer would have run out anyway.
WAIT_SECONDS = 60 * 60
# How long one attempt may hold the "being sent" marker: well over the mail server's
# timeout (10 seconds in capy-project), so a crashed attempt doesn't block retries long.
SENDING_SECONDS = 2 * 60


class CacheDoesNotKeep(Exception):
    """The cache accepted the email but doesn't give it back (e.g. a dummy cache)."""


def as_data(message):
    """The parts of an email as plain data: unlike the email object itself, plain data
    still reads back after a Django upgrade and in a cache that stores JSON. Code that
    reads it (from_data) must keep reading this format for WAIT_SECONDS after a change.
    Attachments aren't carried (queue_email sends emails with attachments at once)."""
    return {
        "subject": message.subject,
        "body": message.body,
        "from_email": message.from_email,
        "to": list(message.to),
        "cc": list(message.cc),
        "bcc": list(message.bcc),
        "reply_to": list(message.reply_to),
        "headers": dict(message.extra_headers),
        "content_subtype": message.content_subtype,
        "alternatives": [
            [content, mimetype] for content, mimetype in getattr(message, "alternatives", [])
        ],
    }


def from_data(data):
    """The email again, from as_data(). Raises KeyError or TypeError for anything else."""
    message = EmailMultiAlternatives(
        data["subject"],
        data["body"],
        data["from_email"],
        data["to"],
        bcc=data["bcc"],
        cc=data["cc"],
        reply_to=data["reply_to"],
        headers=data["headers"],
    )
    message.content_subtype = data["content_subtype"]
    for content, mimetype in data["alternatives"]:
        message.attach_alternative(content, mimetype)
    return message


def store(data):
    """Keeps the email's data in the cache and returns its random key. Raises whatever
    the cache raises when it's down, or CacheDoesNotKeep."""
    key = secrets.token_urlsafe(32)
    cache_key = CACHE_KEY_PREFIX + key
    cache.set(cache_key, data, WAIT_SECONDS)
    if cache.get(cache_key) is None:
        raise CacheDoesNotKeep
    return key


def load(key):
    """The email's data kept under the key, or None once it's gone."""
    return cache.get(CACHE_KEY_PREFIX + key)


def start_sending(key):
    """Marks the email as being sent; False if another attempt already is."""
    return cache.add(SENDING_KEY_PREFIX + key, True, SENDING_SECONDS)


def stop_sending(key):
    cache.delete(SENDING_KEY_PREFIX + key)


def discard(key):
    """Removes the email and its marker: it was sent, or won't be."""
    cache.delete_many([CACHE_KEY_PREFIX + key, SENDING_KEY_PREFIX + key])
