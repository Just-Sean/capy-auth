"""manage.py mark_email_verified <email>: confirms an address by hand, for someone who
can't receive the code yet (e.g. a superuser on a new server before email is set up)."""

from django.core.management.base import BaseCommand, CommandError

from capy_auth.account.services import AddressNotConfirmed, mark_email_verified


class Command(BaseCommand):
    help = "Marks an email address as confirmed on the account using it."

    def add_arguments(self, parser):
        parser.add_argument("email")

    def handle(self, *args, email, **options):
        try:
            user = mark_email_verified(email)
        except AddressNotConfirmed as error:
            raise CommandError(str(error)) from error
        self.stdout.write(self.style.SUCCESS(f"Confirmed {email.strip().lower()} for {user}."))
