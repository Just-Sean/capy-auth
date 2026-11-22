"""capy-auth's emails are sent by the background worker. The finished email waits in the
cache under a random key until it's sent, and the job carries only the key, so codes and
reset links never go into the job or the database."""

import logging
from smtplib import SMTPRecipientsRefused

import pytest
from allauth.account.adapter import DefaultAccountAdapter
from django.core import mail
from django.core.cache import cache
from django.core.mail import EmailMessage, EmailMultiAlternatives
from django.tasks import default_task_backend, task_backends

from capy_auth.emails import sending, tasks
from capy_auth.emails.tasks import EmailNotSent, queue_email, send_queued_email
from tests.accounts import CHANGE_PASSWORD, NEW_PASSWORD, PASSWORD, RESET, code_from, sign_up

QUEUE_ONLY = {"default": {"BACKEND": "django.tasks.backends.dummy.DummyBackend"}}
FIELDS = ("subject", "body", "from_email", "to", "cc", "bcc", "reply_to", "extra_headers")
FIELDS += ("content_subtype", "alternatives", "attachments")


@pytest.fixture
def queued(settings):
    """Jobs are kept, not run, as if the worker hadn't got to them yet."""
    settings.TASKS = QUEUE_ONLY
    default_task_backend.clear()
    return default_task_backend


@pytest.fixture
def rendered(monkeypatch):
    """Every email allauth built, before it went into the cache."""
    built = []
    original = DefaultAccountAdapter.render_mail

    def keep(self, *args, **kwargs):
        built.append(original(self, *args, **kwargs))
        return built[-1]

    monkeypatch.setattr(DefaultAccountAdapter, "render_mail", keep)
    return built


@pytest.fixture
def mail_server_refuses(monkeypatch):
    """The mail server refuses every email, naming the address as real servers do."""

    def refuse(self, fail_silently=False):
        raise SMTPRecipientsRefused({"eve@example.com": (550, b"no such user")})

    monkeypatch.setattr(EmailMultiAlternatives, "send", refuse)


def run_jobs(backend):
    for result in list(backend.results):
        backend.results.remove(result)
        send_queued_email.call(*result.args, **result.kwargs)


def parts(message):
    return {name: getattr(message, name) for name in FIELDS}


def email_is_queued(key):
    return sending.load(key) is not None


# --- The job carries only a key ------------------------------------------------------


@pytest.mark.django_db
def test_signing_up_queues_the_email_with_only_a_key_in_the_job(client, queued, rendered):
    sign_up(client)
    assert mail.outbox == []  # not sent during the request
    [result] = queued.results
    assert result.task.func is send_queued_email.func
    [key] = result.args
    assert len(key) >= 40 and result.kwargs == {}
    assert code_from(rendered[0]) not in repr(result.args)
    assert email_is_queued(key)


@pytest.mark.django_db
def test_a_reset_link_waits_in_the_cache_not_the_job(client, ada, queued):
    client.post(RESET, {"email": "ada@example.com"})
    [result] = queued.results
    assert "/password/reset/key/" not in repr(result.args)
    run_jobs(queued)
    assert "/password/reset/key/" in mail.outbox[0].body


# --- Every allauth email arrives exactly as built ------------------------------------


def arrives_as_built(rendered, queued):
    run_jobs(queued)
    assert len(mail.outbox) == len(rendered) >= 1
    for built, sent in zip(rendered, mail.outbox, strict=True):
        assert parts(sent) == parts(built)


@pytest.mark.django_db
def test_signup_code_arrives(client, queued, rendered):
    sign_up(client)
    arrives_as_built(rendered, queued)


@pytest.mark.django_db
def test_a_resent_code_arrives_and_works(client, queued, rendered):
    code_url = sign_up(client).url
    run_jobs(queued)
    cache.clear()  # past allauth's resend cooldown (the first email is already sent)
    client.post(code_url, {"action": "resend"})
    arrives_as_built(rendered, queued)
    assert client.post(code_url, {"code": code_from(mail.outbox[1])}).status_code == 302


@pytest.mark.django_db
@pytest.mark.parametrize("email", ["ada@example.com", "nobody@example.com"])
def test_reset_and_unknown_address_emails_arrive(client, ada, queued, rendered, email):
    client.post(RESET, {"email": email})
    arrives_as_built(rendered, queued)
    assert mail.outbox[0].to == [email]


@pytest.mark.django_db
def test_account_already_exists_and_password_changed_emails_arrive(client, ada, queued, rendered):
    sign_up(client, email="ada@example.com")
    client.force_login(ada)
    client.post(
        CHANGE_PASSWORD,
        {"oldpassword": PASSWORD, "password1": NEW_PASSWORD, "password2": NEW_PASSWORD},
    )
    arrives_as_built(rendered, queued)
    assert len(mail.outbox) == 2


@pytest.mark.django_db
def test_a_non_ascii_address_arrives(client, queued, rendered):
    sign_up(client, email="eve@exämple.com")
    arrives_as_built(rendered, queued)


# --- What the cache keeps -------------------------------------------------------------


def test_every_part_of_an_email_survives_the_cache():
    message = EmailMultiAlternatives(
        "Ünïcödé 🦫",
        "Grüße",
        "accounts@example.com",
        ["zoë@exämple.com"],
        bcc=["audit@example.com"],
        cc=["cc@example.com"],
        reply_to=["support@example.com"],
        headers={"X-Mailer-Tag": "signup"},
    )
    message.attach_alternative("<p>Grüße</p>", "text/html")
    queue_email(message)
    [sent] = mail.outbox
    assert parts(sent) == parts(message)


def test_an_html_only_email_stays_html():
    # allauth builds one when a project has only *_message.html templates.
    message = EmailMessage("Hi", "<p>Hello</p>", "accounts@example.com", ["eve@example.com"])
    message.content_subtype = "html"
    queue_email(message)
    assert mail.outbox[0].content_subtype == "html"


def test_an_email_with_an_attachment_is_sent_at_once(queued, caplog):
    message = EmailMessage("Hi", "Hello", "accounts@example.com", ["eve@example.com"])
    message.attach("note.txt", "hello", "text/plain")
    with caplog.at_level(logging.WARNING, logger="capy_auth"):
        queue_email(message)
    assert len(mail.outbox) == 1 and queued.results == []
    assert "attachments" in caplog.text


# --- Sending once, and failures --------------------------------------------------------


@pytest.mark.django_db
def test_the_job_sends_the_email_once(client, queued):
    sign_up(client)
    [key] = queued.results[0].args
    send_queued_email.call(key)
    send_queued_email.call(key)  # run twice by mistake
    assert len(mail.outbox) == 1
    assert not email_is_queued(key)


@pytest.mark.django_db
def test_a_second_run_while_the_first_is_sending_sends_nothing(client, queued):
    sign_up(client)
    [key] = queued.results[0].args
    assert sending.start_sending(key)  # the first run is sending
    send_queued_email.call(key)
    assert mail.outbox == []
    assert email_is_queued(key)


@pytest.mark.django_db
def test_a_mail_server_failure_keeps_the_email_and_tries_again_later(
    client, queued, mail_server_refuses, caplog
):
    sign_up(client)
    [key] = queued.results[0].args
    queued.clear()
    with caplog.at_level(logging.WARNING, logger="capy_auth"):
        send_queued_email.call(key)
    assert email_is_queued(key)
    [retry] = queued.results
    assert retry.args == [key, 1]
    assert retry.task.run_after is not None
    assert "trying again in 60 seconds" in caplog.text
    assert "eve@example.com" not in caplog.text


@pytest.mark.django_db
def test_after_the_last_try_the_email_is_dropped_without_naming_the_address(
    client, queued, mail_server_refuses, caplog
):
    sign_up(client)
    [key] = queued.results[0].args
    with caplog.at_level(logging.ERROR, logger="capy_auth"):
        with pytest.raises(EmailNotSent) as raised:
            send_queued_email.call(key, len(tasks.RETRY_DELAYS))
    assert "eve@example.com" not in str(raised.value) and raised.value.__cause__ is None
    assert not email_is_queued(key)
    assert "couldn't be sent (SMTPRecipientsRefused)" in caplog.text
    assert "eve@example.com" not in caplog.text


@pytest.mark.django_db
def test_without_a_queue_that_can_wait_a_failure_isnt_retried(client, mail_server_refuses):
    # The stand-in project runs jobs at once (like capy-project's development): there's
    # no waiting, so the job gives up, and the request still works.
    assert sign_up(client).status_code == 302
    assert mail.outbox == []


@pytest.mark.django_db
def test_an_email_gone_from_the_cache_is_logged_without_its_content(client, queued, caplog):
    sign_up(client)
    [key] = queued.results[0].args
    code = code_from(sending.from_data(sending.load(key)))
    sending.discard(key)  # expired, cleared or evicted
    with caplog.at_level(logging.ERROR, logger="capy_auth"):
        send_queued_email.call(key)
    assert mail.outbox == []
    assert "no longer in the cache" in caplog.text
    assert code not in caplog.text


def test_unreadable_data_in_the_cache_is_dropped(caplog):
    cache.set(sending.CACHE_KEY_PREFIX + "k", {"subject": "x"}, 60)
    with caplog.at_level(logging.ERROR, logger="capy_auth"):
        send_queued_email.call("k")
    assert mail.outbox == []
    assert "couldn't be read" in caplog.text


# --- When the cache or the job queue is down --------------------------------------------


@pytest.mark.django_db
def test_when_the_cache_is_down_the_email_is_sent_at_once(client, queued, monkeypatch, caplog):
    def cache_down(*args, **kwargs):
        raise ConnectionError("cache unavailable")  # as the cache raises when it's down

    monkeypatch.setattr(sending.cache, "set", cache_down)
    monkeypatch.setattr(sending, "load", lambda key: None)
    with caplog.at_level(logging.WARNING, logger="capy_auth"):
        queue_email(EmailMessage("Hi", "Hello", "accounts@example.com", ["eve@example.com"]))
    assert len(mail.outbox) == 1
    assert queued.results == []
    assert "the cache is unavailable" in caplog.text


@pytest.mark.django_db
def test_a_cache_that_keeps_nothing_still_delivers(client, settings):
    settings.CACHES = {"default": {"BACKEND": "django.core.cache.backends.dummy.DummyCache"}}
    sign_up(client)
    assert len(mail.outbox) == 1


@pytest.mark.django_db
def test_when_the_job_queue_is_down_the_email_is_sent_and_nothing_is_left(client, monkeypatch):
    class Down:
        def enqueue(self, *args, **kwargs):
            raise ConnectionError("job queue unavailable")

    monkeypatch.setattr(tasks, "send_queued_email", Down())
    assert sign_up(client).status_code == 302
    assert len(mail.outbox) == 1
    assert not [key for key in cache._cache if sending.CACHE_KEY_PREFIX in key]


@pytest.mark.django_db
def test_with_jobs_run_straight_away_the_email_goes_through_the_cache(client, monkeypatch, caplog):
    # The stand-in project runs jobs at once (capy-project's development and tests).
    stored = []
    real_store = sending.store
    monkeypatch.setattr(sending, "store", lambda data: stored.append(1) or real_store(data))
    with caplog.at_level(logging.WARNING, logger="capy_auth"):
        sign_up(client)
    assert stored == [1] and len(mail.outbox) == 1
    assert "during the request" not in caplog.text  # it really went through the queue
    assert not [key for key in cache._cache if sending.CACHE_KEY_PREFIX in key]


def test_after_the_queue_only_fixture_jobs_run_straight_away_again():
    assert type(task_backends["default"]).__name__ == "ImmediateBackend"
