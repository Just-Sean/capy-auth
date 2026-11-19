"""capy-auth's MFA adapter: allauth's, with every MFA secret encrypted before it's
stored (mfa/crypto.py). A project points MFA_ADAPTER at it (see the README); without
it, secrets would be stored readable, so Django's checks stop the site (E008)."""

from allauth.mfa.adapter import DefaultMFAAdapter
from allauth.mfa.models import Authenticator
from django.utils.translation import gettext

from . import crypto


class MFAAdapter(DefaultMFAAdapter):
    def encrypt(self, text):
        return crypto.encrypt(text)

    def decrypt(self, encrypted_text):
        return crypto.decrypt(encrypted_text)

    def generate_authenticator_name(self, user, type):
        """The name a new passkey or security key gets unless the person types one:
        "Passkey 1", "Passkey 2", … (allauth's are "Master key", "Backup key", …)."""
        number = Authenticator.objects.filter(user_id=user.pk, type=type).count() + 1
        return gettext("Passkey {number}").format(number=number)
