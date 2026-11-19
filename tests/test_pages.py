"""allauth's pages render inside the project's layout.html, under capy-project's strict
Content Security Policy, with daisyUI classes so capy-theme styles them, and accessible
labels, help text and errors."""

import hashlib
import re
import secrets
from pathlib import Path

import allauth
import pytest
from allauth.account.models import EmailAddress
from allauth.account.views import EmailView
from django import forms
from django.contrib.auth import get_user_model
from django.template import Context, Template
from django.template.base import Origin
from django.test import Client
from django.urls import NoReverseMatch, reverse

from tests.helpers import check_page, dangling_describedby
from tests.test_csp import blocked_in

ALLAUTH_TEMPLATES = Path(allauth.__file__).resolve().parent / "templates"
CAPY_AUTH_TEMPLATES = Path(__file__).resolve().parent.parent / "src/capy_auth/templates"
# The allauth apps the stand-in project installs; each later feature adds its own.
CHECKED_FOLDERS = ("allauth", "account", "usersessions", "mfa")
PASSWORD = secrets.token_urlsafe()

# allauth's account pages that need no link key, as seen logged out and logged in.
LOGGED_OUT_PAGES = [
    "account_login",
    "account_signup",
    "account_reset_password",
    "account_reset_password_done",
    "account_reset_password_from_key_done",
    "account_inactive",
]
LOGGED_IN_PAGES = [
    "account_email",
    "account_change_password",
    "account_reauthenticate",
    "account_logout",
    "usersessions_list",
    "mfa_index",
]
# allauth pages capy-auth copies to change one thing: the inline style the policy blocks.
COPIED_PAGES = ["account/email_change.html", "account/phone_change.html"]


@pytest.fixture
def user():
    return get_user_model().objects.create_user(
        username="ada", email="ada@example.com", password=PASSWORD
    )


@pytest.fixture
def user_with_email(user):
    EmailAddress.objects.create(user=user, email=user.email, primary=True, verified=True)
    return user


def render(source, **context):
    origin = Origin(name="test.html", template_name="test.html")
    return Template("{% load allauth %}" + source, origin=origin).render(Context(context))


# --- Every page --------------------------------------------------------------------


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
def test_a_bad_password_reset_link_renders_inside_the_layout(client):
    url = reverse("account_reset_password_from_key", kwargs={"uidb36": "zz", "key": "bad"})
    check_page(client.get(url))


def test_email_is_verified_by_code_only_so_there_is_no_link_page():
    # With verification by code, allauth has no confirmation-link page to render or
    # attack (the code page is checked with the signup flow in test_email_password.py).
    with pytest.raises(NoReverseMatch):
        reverse("account_confirm_email", args=["any-key"])


@pytest.mark.django_db
def test_the_logged_in_menu_from_allauth_is_left_out_and_the_title_is_set(client, user):
    client.force_login(user)
    page = check_page(client.get(reverse("account_change_password")))
    assert "Sign Out</a>" not in page
    assert re.search(r"<title>\s*Change Password\s*</title>", page)


# --- Forms posted with errors --------------------------------------------------------


@pytest.mark.django_db
def test_login_with_a_wrong_password_shows_the_error_at_the_top(client, user):
    page = check_page(
        client.post(
            reverse("account_login"), {"login": "ada@example.com", "password": PASSWORD + "x"}
        )
    )
    assert re.search(r'<div role="alert" class="alert alert-error">[^<]+</div>', page)


@pytest.mark.django_db
def test_markup_typed_into_a_form_is_shown_escaped(client):
    page = check_page(
        client.post(
            reverse("account_login"), {"login": '"><script>x</script>@example.com', "password": "y"}
        )
    )
    assert "<script>x" not in page
    assert "&lt;script&gt;x" in page


@pytest.mark.django_db
def test_forms_refuse_a_post_without_the_csrf_token():
    response = Client(enforce_csrf_checks=True).post(
        reverse("account_login"), {"login": "ada@example.com", "password": "x"}
    )
    assert response.status_code == 403


@pytest.mark.django_db
def test_field_errors_are_linked_to_their_inputs(client):
    # Django marks an input with errors aria-invalid and points it at "<id>_error";
    # check_page checks every such id exists, so screen readers read the error out.
    page = check_page(client.post(reverse("account_signup"), {}))
    assert re.search(r'<input[^>]*aria-invalid="true"', page)
    assert re.search(r'<div id="id_email_error">\s*<p><strong>Error:</strong> ', page)
    assert "input input-error w-full text-base" in page


@pytest.mark.django_db
def test_password_change_errors_are_linked_to_their_inputs(client, user):
    client.force_login(user)
    check_page(client.post(reverse("account_change_password"), {}))


@pytest.mark.django_db
def test_password_help_text_renders_as_html_and_is_linked_to_its_input(client, settings):
    settings.AUTH_PASSWORD_VALIDATORS = [
        {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
        {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    ]
    page = check_page(client.get(reverse("account_signup")))
    assert re.search(r'<div class="label whitespace-normal" id="id_password1_helptext"><ul>', page)
    assert re.search(r'<input[^>]*aria-describedby="id_password1_helptext"', page)


@pytest.mark.django_db
def test_form_fields_have_visible_labels_and_daisyui_inputs(client):
    page = check_page(client.get(reverse("account_login")))
    for field in ("id_login", "id_password"):
        assert f'<label class="fieldset-legend" for="{field}">' in page
        assert re.search(rf'<input[^>]*class="input w-full text-base"[^>]*id="{field}"', page)
    assert re.search(r'<button[^>]*class="btn btn-primary"', page)


# --- The fields element on its own -----------------------------------------------------


class SampleForm(forms.Form):
    name = forms.CharField(widget=forms.TextInput(attrs={"class": "wide"}), help_text="Seen")
    remember = forms.BooleanField(help_text="Read the terms")
    kind = forms.ChoiceField(choices=[("a", "A")])
    note = forms.CharField(widget=forms.Textarea)
    pick = forms.ChoiceField(choices=[("a", "A"), ("b", "B")], widget=forms.RadioSelect)
    many = forms.MultipleChoiceField(choices=[("a", "A")], widget=forms.CheckboxSelectMultiple)
    upload = forms.FileField()
    secret = forms.CharField(widget=forms.HiddenInput)


def render_fields(form):
    return render("{% element fields form=form %}{% endelement %}", form=form)


@pytest.mark.parametrize(
    ("field", "expected"),
    [
        ("name", r'class="wide input w-full text-base"'),
        ("remember", r'class="checkbox"'),
        ("kind", r'class="select w-full text-base"'),
        ("note", r'class="textarea w-full text-base"'),
        ("pick", r'<input type="radio" name="pick" value="a" class="radio"'),
        ("many", r'<input type="checkbox" name="many" value="a" class="checkbox"'),
        ("upload", r'class="file-input w-full"'),
    ],
)
def test_inputs_get_daisyuis_class_for_their_kind(field, expected):
    assert re.search(expected, render_fields(SampleForm()))


def test_radio_and_checkbox_groups_are_fieldsets_with_a_legend():
    html = render_fields(SampleForm())
    assert '<legend class="fieldset-legend">Pick</legend>' in html
    assert '<legend class="fieldset-legend">Many</legend>' in html
    assert 'for=""' not in html


def test_help_text_is_linked_and_hidden_fields_have_no_label():
    html = render_fields(SampleForm())
    assert 'aria-describedby="id_name_helptext"' in html
    assert 'aria-describedby="id_remember_helptext"' in html
    assert re.search(r'<input type="hidden" name="secret"[^>]*id="id_secret"', html)
    assert "Secret" not in html


def test_errors_on_a_hidden_field_are_shown():
    form = SampleForm(data={"name": "x", "remember": "on"})
    assert not form.is_valid()
    assert "(Hidden field secret) This field is required." in render_fields(form)


# --- The field element (fields a page writes out itself) -------------------------------


def test_field_element_required_disabled_checked_and_value_zero():
    html = render(
        '{% element field type="text" id="a" name="a" required=True disabled=True'
        " value=0 %}{% slot label %}A{% endslot %}{% endelement %}"
        '{% element field type="checkbox" id="b" name="b" checked=True %}'
        "{% slot label %}B{% endslot %}{% endelement %}"
        '{% element field type="radio" id="c" name="c" value="x" %}'
        "{% slot label %}C{% endslot %}{% endelement %}"
    )
    assert re.search(
        r'<input class="input w-full text-base"\s+required\s+disabled[^>]*value="0"', html
    )
    assert re.search(r'<input class="checkbox"[^>]*checked[^>]*type="checkbox"', html)
    assert re.search(r'<input class="radio"[^>]*value="x"\s+type="radio"', html)


def test_field_element_links_its_help_text_and_errors():
    html = render(
        '{% element field type="email" id="e" name="email" errors=errors %}'
        "{% slot label %}Email{% endslot %}{% slot help_text %}Pending{% endslot %}"
        "{% endelement %}",
        errors=forms.utils.ErrorList(["Enter a valid email address."]),
    )
    assert 'aria-invalid="true"' in html
    assert 'aria-describedby="e_helptext e_error"' in html
    assert dangling_describedby(html) == []
    assert "<strong>Error:</strong> Enter a valid email address." in html


def test_field_element_textarea_keeps_its_value():
    html = render(
        '{% element field type="textarea" id="t" name="t" rows=3 %}'
        "{% slot label %}T{% endslot %}{% slot value %}hello{% endslot %}{% endelement %}"
    )
    assert re.search(r'<textarea class="textarea w-full text-base"[^>]*rows="3"[^>]*>hello<', html)


# --- Buttons and badges ------------------------------------------------------------


def test_button_with_href_is_a_link_and_without_is_a_button():
    html = render(
        '{% element button href="/x/" tags="primary,minor" %}Go{% endelement %}'
        '{% element button type="submit" name="n" value="v" tags="secondary" %}Send'
        "{% endelement %}"
    )
    assert re.search(r'<a href="/x/"\s+class="btn btn-primary btn-sm"\s*>\s*Go\s*</a>', html)
    assert re.search(
        r'<button\s+class="btn btn-secondary"\s+name="n"\s+value="v"\s+type="submit"\s*>'
        r"\s*Send\s*</button>",
        html,
    )


def test_a_forms_untagged_submit_button_is_the_primary_action():
    html = render('{% element button type="submit" %}Save{% endelement %}')
    assert 'class="btn btn-primary"' in html
    # A button that submits another form (form=…) isn't this form's main action.
    other = render('{% element button type="submit" form="other" %}Go{% endelement %}')
    assert 'class="btn"' in other


def test_button_tags_are_matched_whole():
    assert re.search(r'<button\s+class="btn"\s*>', render("{% element button %}Go{% endelement %}"))
    assert "btn-outline" not in render('{% element button tags="outlined" %}Go{% endelement %}')


def test_a_badges_explanation_is_written_out_for_screen_readers():
    html = render('{% element badge title="Not a passkey" %}Key{% endelement %}')
    assert '<span class="sr-only">(Not a passkey)</span>' in html


# --- Messages, scripts and the copied pages ------------------------------------------


@pytest.mark.django_db
def test_a_message_after_a_redirect_shows_in_the_layouts_status_region(client, user_with_email):
    response = client.post(
        reverse("account_login"),
        {"login": "ada@example.com", "password": PASSWORD},
        follow=True,
    )
    page = check_page(response)
    status = re.search(r'<div role="status">(.*?)</div>', page, re.DOTALL).group(1)
    # Named by email, not by the username allauth made up (ACCOUNT_USER_DISPLAY).
    assert "Successfully signed in as ada@example.com." in status


@pytest.mark.django_db
def test_the_email_page_puts_its_scripts_and_json_data_in_the_head(client, user_with_email):
    client.force_login(user_with_email)
    page = check_page(client.get(reverse("account_email")))
    head, body = page.split("</head>", 1)
    assert '<script src="/static/account/js/account.js">' in head
    assert '<script src="/static/account/js/onload.js">' in head
    assert 'data-allauth-onload="allauth.account.forms.manageEmailForm"' in head
    assert "<script" not in body
    assert re.search(r'<input class="radio"[^>]*value="ada@example.com"[^>]*checked', page)


@pytest.mark.django_db
def test_the_change_email_page_with_a_pending_change_uses_hidden_not_style(
    client, user_with_email, monkeypatch, settings
):
    # allauth picks this page once, when it loads, so point its view at it.
    settings.ACCOUNT_CHANGE_EMAIL = True
    monkeypatch.setattr(EmailView, "template_name", "account/email_change.html")
    EmailAddress.objects.create(
        user=user_with_email, email="next@example.com", primary=False, verified=False
    )
    client.force_login(user_with_email)
    page = check_page(client.get(reverse("account_email")))
    assert re.search(r'<form hidden\s+id="pending-email"', page)
    assert 'form="pending-email"' in page


@pytest.mark.parametrize("name", COPIED_PAGES)
def test_copied_pages_match_allauths_apart_from_the_inline_style(name):
    # Fails when an allauth upgrade changes the original: update the copy to match.
    original = (ALLAUTH_TEMPLATES / name).read_text(encoding="utf-8")
    copy = (CAPY_AUTH_TEMPLATES / name).read_text(encoding="utf-8")
    copy = re.sub(r"\{% comment %\}.*?\{% endcomment %\}\n", "", copy, count=1, flags=re.DOTALL)
    assert copy == original.replace('style="display: none"', "hidden")


# allauth pages capy-auth rewrites rather than copies, with a fingerprint of the allauth
# original each was written from (allauth 65.22.1).
REWRITTEN_PAGES = {
    "account/email.html": "b828763e520b3a1241e815b6608bb8a2438758a699cdc66ee9619713597f9157",
    "account/password_reset_from_key.html": (
        "a440b3cb49b8f55641d26cf3146a028f21a9e67ed00d1b61676d3a14ce5ba039"
    ),
    "account/password_reset_from_key_done.html": (
        "84a7e4eeba8bf3ecfc5fae59f8658e7ba6edd9f521383e4d87afe42b55697707"
    ),
    "account/reauthenticate.html": (
        "9e2a69f8965f618e01c6cb8efcb51ace5f6d3da49b5ef94b7f5f769730a55b85"
    ),
    "account/base_reauthenticate.html": (
        "3c03c732d9f8e91f5defe4d03e6286e34db65b0a6b0000e60a129cd34173b5fc"
    ),
    "usersessions/usersession_list.html": (
        "232143c3f98d9d9fd03c97fb0516f9af0a61cf069edf123e2ed90ae5fa814808"
    ),
}


@pytest.mark.parametrize(("name", "fingerprint"), REWRITTEN_PAGES.items())
def test_rewritten_pages_were_written_from_allauths_current_version(name, fingerprint):
    # Fails when an allauth upgrade changes the original: check the rewrite against the
    # new version (fields, actions, scripts), then update the fingerprint.
    original = (ALLAUTH_TEMPLATES / name).read_bytes()
    assert hashlib.sha256(original).hexdigest() == fingerprint


def element_names(source):
    """The attributes, slots and named slots an element template uses."""
    return set(re.findall(r"\b(?:attrs|slots)\.(\w+)|\{% slot (\w+)", source))


@pytest.mark.parametrize(
    "name", sorted(p.name for p in (CAPY_AUTH_TEMPLATES / "allauth/elements").glob("*.html"))
)
def test_element_overrides_keep_everything_allauths_version_uses(name):
    # Fails when an allauth upgrade gives an element something new to show.
    original = (ALLAUTH_TEMPLATES / "allauth/elements" / name).read_text(encoding="utf-8")
    override = (CAPY_AUTH_TEMPLATES / "allauth/elements" / name).read_text(encoding="utf-8")
    assert element_names(original) <= element_names(override)


def allauth_template_names():
    return sorted(
        str(path.relative_to(ALLAUTH_TEMPLATES))
        for folder in CHECKED_FOLDERS
        for path in (ALLAUTH_TEMPLATES / folder).rglob("*.html")
    )


def test_every_allauth_template_in_use_has_nothing_the_policy_blocks():
    # The template Django actually uses for each name: capy-auth's where it overrides
    # allauth's, allauth's otherwise. Emails aren't pages, so the policy doesn't apply.
    # Read as files, not compiled: some (passkeys, feature 12) need apps not installed.
    problems = {}
    for name in allauth_template_names():
        if "/email/" in name:
            continue
        override = CAPY_AUTH_TEMPLATES / name
        source = (override if override.exists() else ALLAUTH_TEMPLATES / name).read_text(
            encoding="utf-8"
        )
        if blocked := blocked_in(source):
            problems[name] = blocked
    assert problems == {}
