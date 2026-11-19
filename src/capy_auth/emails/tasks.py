"""Sends capy-auth's emails from the project's background worker (Django's Tasks API).
An email stays in the cache until it's sent; if the mail server fails, the job tries
again a few times within the hour. Logs say what happened to an email, never what's in
it or who it's for."""

import logging
from datetime import timedelta
from smtplib import SMTPException

from django.tasks import default_task_backend, task
from django.utils import timezone

from . import sending

logger = logging.getLogger("capy_auth")

# Waits before each new try after the mail server fails: about 33 minutes in all, inside
# the hour an email waits.
RETRY_DELAYS = (60, 2 * 60, 5 * 60, 10 * 60, 15 * 60)


class EmailNotSent(Exception):
    """Sending failed for good. Its message names only the kind of error, never an
    address (mail server errors can contain one)."""


@task()
def send_queued_email(key, attempt=0):
    """Sends the email kept under the key, once. The key and the attempt number are all
    the job carries."""
    data = sending.load(key)
    if data is None:
        logger.error(
            "A queued email was no longer in the cache (it waited over %s seconds, or "
            "the cache was cleared, restarted or full); the person can ask for a new one.",
            sending.WAIT_SECONDS,
        )
        return
    if not sending.start_sending(key):
        return  # another run of this job is sending it
    try:
        message = sending.from_data(data)
    except KeyError, TypeError:
        sending.discard(key)
        logger.error("A queued email couldn't be read from the cache; it's dropped.")
        return
    try:
        message.send()
    except (SMTPException, OSError) as error:
        sending.stop_sending(key)
        retry_or_give_up(key, attempt, type(error).__name__)
        return
    sending.discard(key)


def retry_or_give_up(key, attempt, error_name):
    """After the mail server failed: queue the job again later, or give up."""
    if attempt < len(RETRY_DELAYS) and default_task_backend.supports_defer:
        delay = RETRY_DELAYS[attempt]
        run_after = timezone.now() + timedelta(seconds=delay)
        send_queued_email.using(run_after=run_after).enqueue(key, attempt + 1)
        logger.warning(
            "Sending a queued email failed (%s); trying again in %s seconds.", error_name, delay
        )
        return
    sending.discard(key)
    logger.error("A queued email couldn't be sent (%s); it's dropped.", error_name)
    raise EmailNotSent(f"The mail server failed ({error_name}).") from None


def queue_email(message):
    """Sends the email from the worker. Sends it now instead when it has attachments
    (the queue doesn't carry them), or when the cache or the job queue is unavailable,
    so signup and password resets keep working."""
    if message.attachments:
        send_now(message, "it has attachments, which the queue doesn't carry")
        return
    data = sending.as_data(message)
    try:
        key = sending.store(data)
    except Exception:  # whatever the cache backend raises when it's down
        send_now(message, "the cache is unavailable or doesn't keep data", exc_info=True)
        return
    try:
        send_queued_email.enqueue(key)
    except Exception:  # whatever the job backend raises when it's down
        sending.discard(key)
        send_now(message, "the job queue is unavailable", exc_info=True)


def send_now(message, reason, exc_info=False):
    logger.warning(
        "An email is sent during the request instead of by the worker: %s.",
        reason,
        exc_info=exc_info,
    )
    message.send()
