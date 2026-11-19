"""capy-auth's own account pages (allauth provides the rest)."""

from django.contrib.auth.decorators import login_required
from django.shortcuts import render


@login_required
def account_page(request):
    """Where people land after logging in: their email and the account pages."""
    return render(request, "capy_auth/account.html")
