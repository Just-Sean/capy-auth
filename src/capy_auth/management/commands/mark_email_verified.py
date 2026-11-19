"""manage.py mark_email_verified <email>: confirms an address by hand, for someone who
can't receive the code yet (e.g. a superuser on a new server before email is set up)."""

from django.core.management.base import BaseCommand, CommandError

from capy_auth.account.services import (
    AddressNotConfirmed,
    mark_email_verified,
    normalized_address,
)


class Command(BaseCommand):
    help = "Marks an email address as confirmed on the account using it."

    def add_arguments(self, parser):
        parser.add_argument("email", help="the address to confirm, e.g. you@example.com")

    def handle(self, *args, email, **options):
        try:
            user, is_main = mark_email_verified(email)
        except AddressNotConfirmed as error:
            raise CommandError(str(error)) from error
        main = " It's the account's main address." if is_main else ""
        message = f"Confirmed {normalized_address(email)} for {user}.{main}"
        self.stdout.write(self.style.SUCCESS(message))
