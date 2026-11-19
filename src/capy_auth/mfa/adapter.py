"""capy-auth's MFA adapter: allauth's, with every MFA secret encrypted before it's
stored (mfa/crypto.py). A project points MFA_ADAPTER at it (see the README); without
it, secrets would be stored readable, so Django's checks stop the site (E008)."""

from allauth.mfa.adapter import DefaultMFAAdapter

from . import crypto


class MFAAdapter(DefaultMFAAdapter):
    def encrypt(self, text):
        return crypto.encrypt(text)

    def decrypt(self, encrypted_text):
        return crypto.decrypt(encrypted_text)
