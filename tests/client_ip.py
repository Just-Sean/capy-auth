"""A small copy of capy-project's client_ip (config/login_limits.py), which django-axes
uses for the visitor's address (AXES_CLIENT_IP_CALLABLE): behind one proxy you control,
only the last X-Forwarded-For entry (the one the proxy adds) counts; earlier entries are
whatever the visitor sent."""

import ipaddress

from django.conf import settings


def client_ip(request):
    connection = request.META.get("REMOTE_ADDR", "")
    if settings.BEHIND_PROXY:
        added_by_proxy = request.META.get("HTTP_X_FORWARDED_FOR", "").split(",")[-1].strip()
        try:
            return str(ipaddress.ip_address(added_by_proxy))
        except ValueError:
            return connection
    return connection
