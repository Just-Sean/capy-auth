"""capy-auth's emails are sent by the background worker. The finished email waits in the
cache under a random key, and the job carries only the key, so codes and reset links
never go into the job or the database."""

import logging

import pytest
from django.core import mail
from django.core.cache import cache
from django.tasks import default_task_backend

from capy_auth.emails import sending
from capy_auth.emails.tasks import send_queued_email
from tests.accounts import RESET, code_from, sign_up

QUEUE_ONLY = {"default": {"BACKEND": "django.tasks.backends.dummy.DummyBackend"}}


@pytest.fixture
def queued(settings):
    """Jobs are kept, not run, as if the worker hadn't got to them yet."""
    settings.TASKS = QUEUE_ONLY
    default_task_backend.clear()
    return default_task_backend


def queued_keys(backend):
    return [result.args[0] for result in backend.results]


@pytest.mark.django_db
def test_signing_up_queues_the_email_with_only_a_key_in_the_job(client, queued):
    sign_up(client)
    assert mail.outbox == []  # not sent during the request
    [result] = queued.results
    assert result.task.func is send_queued_email.func
    [key] = result.args
    assert len(key) >= 40 and result.kwargs == {}
    code = code_from(sending.take(key))
    assert code not in repr(result.args)


@pytest.mark.django_db
def test_the_job_sends_the_email_once(client, queued):
    sign_up(client)
    [key] = queued_keys(queued)
    send_queued_email.call(key)
    assert len(mail.outbox) == 1
    assert cache.get(sending.CACHE_KEY_PREFIX + key) is None  # gone from the cache
    send_queued_email.call(key)  # run twice by mistake
    assert len(mail.outbox) == 1


@pytest.mark.django_db
def test_a_reset_link_waits_in_the_cache_not_the_job(client, ada, queued):
    client.post(RESET, {"email": "ada@example.com"})
    [result] = queued.results
    assert "/password/reset/key/" not in repr(result.args)
    send_queued_email.call(result.args[0])
    assert "/password/reset/key/" in mail.outbox[0].body


@pytest.mark.django_db
def test_an_expired_email_is_dropped_and_logged_without_its_content(client, queued, caplog):
    sign_up(client)
    [key] = queued_keys(queued)
    code = code_from(sending.from_data(cache.get(sending.CACHE_KEY_PREFIX + key)))
    cache.delete(sending.CACHE_KEY_PREFIX + key)  # as if an hour had passed
    with caplog.at_level(logging.ERROR, logger="capy_auth"):
        send_queued_email.call(key)
    assert mail.outbox == []
    assert "expired before the worker sent it" in caplog.text
    assert code not in caplog.text


@pytest.mark.django_db
def test_when_the_cache_is_down_the_email_is_sent_at_once(client, queued, monkeypatch, caplog):
    def cache_down(message):
        raise ConnectionError("cache unavailable")  # as the cache raises when it's down

    monkeypatch.setattr(sending, "store", cache_down)
    with caplog.at_level(logging.WARNING, logger="capy_auth"):
        sign_up(client)
    assert len(mail.outbox) == 1
    assert queued.results == []
    assert "sent during the request instead of by the worker" in caplog.text
    assert code_from(mail.outbox[0]) not in caplog.text


@pytest.mark.django_db
def test_with_jobs_run_straight_away_nothing_is_left_in_the_cache(client):
    # The stand-in project runs jobs at once (capy-project's development and tests).
    sign_up(client)
    assert len(mail.outbox) == 1
    assert not [key for key in cache._cache if sending.CACHE_KEY_PREFIX in key]


def test_an_email_comes_back_from_the_cache_as_it_went_in():
    message = sending.from_data(
        {
            "subject": "Hello",
            "body": "Plain text",
            "from_email": "accounts@example.com",
            "to": ["eve@example.com"],
            "alternatives": [["<p>HTML</p>", "text/html"]],
        }
    )
    again = sending.from_data(sending.as_data(message))
    assert sending.as_data(again) == sending.as_data(message)
    assert again.alternatives == [("<p>HTML</p>", "text/html")]
