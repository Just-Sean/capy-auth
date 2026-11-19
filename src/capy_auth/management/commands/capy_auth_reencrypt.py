"""manage.py capy_auth_reencrypt: re-encrypts every stored MFA secret with the first key
in CAPY_AUTH_ENCRYPTION_KEYS, the step that lets an old key be dropped."""

from django.core.management.base import BaseCommand

from capy_auth.mfa.services import reencrypt_all


class Command(BaseCommand):
    help = (
        "Re-encrypts every stored MFA secret with the first key in "
        "CAPY_AUTH_ENCRYPTION_KEYS, so older keys can be dropped."
    )

    def handle(self, *args, **options):
        done, unreadable = reencrypt_all()
        self.stdout.write(self.style.SUCCESS(f"Re-encrypted {done} authenticators."))
        if unreadable:
            self.stdout.write(
                self.style.WARNING(
                    f"{unreadable} couldn't be read with any key in the list: keep the key "
                    "they were encrypted with, or remove those people's authenticators in "
                    "the admin (they then set two-step sign-in up again)."
                )
            )
        else:
            self.stdout.write("Every secret now uses the first key: older keys can be dropped.")
