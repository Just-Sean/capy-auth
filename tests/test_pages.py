"""allauth's pages render inside the project's layout.html, under capy-project's strict
Content Security Policy, with daisyUI classes so capy-theme styles them."""

import re
import secrets
from pathlib import Path

import allauth
import pytest
from allauth.account.views import EmailView
from django import forms
from django.contrib.auth import get_user_model
from django.template.loader import get_template
from django.urls import reverse

from capy_auth.templatetags.capy_auth_forms import daisy_widget
from tests.test_csp import blocked_in

ALLAUTH_TEMPLATES = Path(allauth.__file__).resolve().parent / "templates"
# The allauth apps the stand-in project installs; each later feature adds its own.
CHECKED_FOLDERS = ("allauth", "account")
PASSWORD = secrets.token_urlsafe()

# allauth's account pages that need no link key, as seen logged out and logged in.
LOGGED_OUT_PAGES = [
    "account_login",
    "account_signup",
    "account_reset_password",
    "account_reset_password_done",
    "account_reset_password_from_key_done",
    "account_email_verification_sent",
    "account_inactive",
]
LOGGED_IN_PAGES = [
    "account_email",
    "account_change_password",
    "account_reauthenticate",
    "account_logout",
]


@pytest.fixture
def user():
    return get_user_model().objects.create_user(
        username="ada", email="ada@example.com", password=PASSWORD
    )


def check_page(response):
    """The page is a full page in layout.html that the strict policy allows."""
    assert response.status_code == 200
    assert "Content-Security-Policy" in response.headers
    page = response.content.decode()
    assert '<div role="status">' in page  # layout.html's messages region
    assert '<main id="main" tabindex="-1">' in page
    assert len(re.findall(r"<h1[\s>]", page)) == 1
    title = re.search(r"<title>(.*?)</title>", page, re.DOTALL).group(1).strip()
    assert title and title != "Untitled page"
    assert "Menu:" not in page  # allauth's own menu is left out
    assert blocked_in(page) == {}
    return page


@pytest.mark.django_db
@pytest.mark.parametrize("name", LOGGED_OUT_PAGES)
def test_logged_out_pages_render_inside_the_layout(client, name):
    check_page(client.get(reverse(name)))


@pytest.mark.django_db
@pytest.mark.parametrize("name", LOGGED_IN_PAGES)
def test_logged_in_pages_render_inside_the_layout(client, user, name):
    client.force_login(user)
    check_page(client.get(reverse(name)))


@pytest.mark.django_db
def test_the_change_email_page_renders_without_inline_styles(client, user, monkeypatch):
    # allauth picks this page (ACCOUNT_CHANGE_EMAIL) once, when it loads, so a settings
    # override can't switch it here; point its view at the page instead.
    monkeypatch.setattr(EmailView, "template_name", "account/email_change.html")
    client.force_login(user)
    response = client.get(reverse("account_email"))
    assert response.templates[0].name == "account/email_change.html"
    check_page(response)


@pytest.mark.django_db
def test_form_fields_have_visible_labels_and_daisyui_inputs(client):
    page = check_page(client.get(reverse("account_login")))
    for field in ("id_login", "id_password"):
        assert f'<label class="label" for="{field}">' in page
        assert re.search(rf'<input[^>]*class="input w-full"[^>]*id="{field}"', page)
    assert re.search(r'<button[^>]*class="btn btn-primary"', page)


def allauth_template_names():
    return sorted(
        str(path.relative_to(ALLAUTH_TEMPLATES))
        for folder in CHECKED_FOLDERS
        for path in (ALLAUTH_TEMPLATES / folder).rglob("*.html")
    )


def test_every_allauth_template_in_use_has_nothing_the_policy_blocks():
    # The template Django actually uses for each name: capy-auth's where it overrides
    # allauth's, allauth's otherwise. Emails aren't pages, so the policy doesn't apply.
    problems = {}
    for name in allauth_template_names():
        if "/email/" in name:
            continue
        source = Path(get_template(name).origin.name).read_text(encoding="utf-8")
        if blocked := blocked_in(source):
            problems[name] = blocked
    assert problems == {}


class SampleForm(forms.Form):
    name = forms.CharField(widget=forms.TextInput(attrs={"class": "wide"}))
    remember = forms.BooleanField()
    kind = forms.ChoiceField(choices=[("a", "A")])
    note = forms.CharField(widget=forms.Textarea)


@pytest.mark.parametrize(
    ("field", "expected"),
    [
        ("name", 'class="wide input w-full"'),
        ("remember", 'class="checkbox"'),
        ("kind", 'class="select w-full"'),
        ("note", 'class="textarea w-full"'),
    ],
)
def test_inputs_get_daisyuis_class_for_their_kind(field, expected):
    assert expected in daisy_widget(SampleForm()[field])
