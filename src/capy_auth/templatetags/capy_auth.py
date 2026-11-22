"""capy-auth's template tags for the project's layout.html: {% capy_auth_menu %}, the
account menu in the nav bar (see the README)."""

from django import template
from django.urls import NoReverseMatch, reverse

from capy_auth.config.selectors import get_auth_settings

register = template.Library()


def admin_url():
    try:
        return reverse("admin:index")
    except NoReverseMatch:  # a project without Django's admin
        return None


@register.inclusion_tag("capy_auth/menu.html", takes_context=True)
def capy_auth_menu(context):
    """Signed out: sign in, and sign up while it's open. Signed in: the person's email,
    their account, the admin for staff, and sign out."""
    user = context.get("user") or context["request"].user  # Django's auth context processor
    return {
        "user": user,
        "csrf_token": context.get("csrf_token"),
        "signup_open": not user.is_authenticated and get_auth_settings().signup_open,
        "admin_url": admin_url() if user.is_authenticated and user.is_staff else None,
    }
