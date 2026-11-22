"""capy-auth's account menu for layout.html ({% capy_auth_menu %}, #37): signed out,
sign in and sign up (while open); signed in, the account, the admin for staff, and sign
out; at most one query."""

import pytest
from django.contrib.auth.models import AnonymousUser
from django.middleware.csrf import get_token
from django.template import RequestContext, Template
from django.urls import NoReverseMatch, reverse

from capy_auth.config.selectors import get_auth_settings
from capy_auth.templatetags import capy_auth as tags
from tests.staff import make_staff

MENU = Template("{% load capy_auth %}{% capy_auth_menu %}")


def menu(rf, user):
    request = rf.get("/")
    request.user = user
    get_token(request)
    return MENU.render(RequestContext(request))


@pytest.mark.django_db
def test_signed_out_it_offers_sign_in_and_sign_up(rf, django_assert_max_num_queries):
    get_auth_settings()  # the record exists, as on a running site
    with django_assert_max_num_queries(1):
        page = menu(rf, AnonymousUser())
    assert f'href="{reverse("account_login")}"' in page
    assert f'href="{reverse("account_signup")}"' in page


@pytest.mark.django_db
def test_with_signup_closed_it_offers_only_sign_in(rf):
    record = get_auth_settings()
    record.signup_open = False
    record.save()
    page = menu(rf, AnonymousUser())
    assert reverse("account_login") in page and reverse("account_signup") not in page


@pytest.mark.django_db
def test_signed_in_it_offers_the_account_and_sign_out(rf, ada, django_assert_num_queries):
    with django_assert_num_queries(0):
        page = menu(rf, ada)
    assert "ada@example.com" in page and reverse("capy_auth_account") in page
    assert f'action="{reverse("account_logout")}"' in page and "csrfmiddlewaretoken" in page
    assert "<script" not in page and "style=" not in page  # the strict CSP
    assert reverse("admin:index") not in page


@pytest.mark.django_db
def test_staff_also_get_the_admin(rf, ada):
    assert reverse("admin:index") in menu(rf, make_staff(ada))


def test_without_the_admin_there_is_no_admin_link(monkeypatch):
    def missing(name):
        raise NoReverseMatch(name)

    monkeypatch.setattr(tags, "reverse", missing)
    assert tags.admin_url() is None


@pytest.mark.django_db
def test_it_works_without_the_request_in_the_template(ada):
    """Django's auth context processor gives it the user (admin needs it too)."""
    from django.template import Context

    assert "ada@example.com" in MENU.render(Context({"user": ada}))
