"""Sends capy-auth's emails from the project's background worker (Django's Tasks API).
Logs say what happened to an email, never what's in it."""

import logging

from django.tasks import task

from . import sending

logger = logging.getLogger("capy_auth")


@task()
def send_queued_email(key):
    """Takes the email out of the cache and sends it. The key is all the job carries."""
    message = sending.take(key)
    if message is None:
        logger.error(
            "A queued email expired before the worker sent it (it waits up to %s "
            "seconds); the person can ask for a new one.",
            sending.WAIT_SECONDS,
        )
        return
    message.send()


def queue_email(message):
    """Sends the email from the worker. If the cache is down, sends it now instead, so
    signup and password resets keep working."""
    try:
        key = sending.store(message)
    except Exception:  # whatever the cache backend raises when it's down
        logger.warning(
            "The cache is unavailable, so an email is sent during the request instead of "
            "by the worker.",
            exc_info=True,
        )
        message.send()
        return
    send_queued_email.enqueue(key)
