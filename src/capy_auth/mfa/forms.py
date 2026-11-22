"""capy-auth's versions of allauth's forms for adding and renaming a passkey or security
key. A project points MFA_FORMS at them (see the README; W006 says when it doesn't).

Every key a person adds can sign them in without a password if their device allows it:
allauth doesn't store whether "passwordless" was ticked, and phones and computers often
save a key as a passkey anyway. So the box is ticked unless the person unticks it, and
its words say what it really does: it asks the device for a fingerprint, face or PIN,
which signing in with only the key needs. Names are capped, as they're shown on pages
and in emails."""

from allauth.mfa.webauthn.forms import AddWebAuthnForm, EditWebAuthnForm
from django import forms
from django.utils.translation import gettext_lazy as _

NAME_MAX_LENGTH = 100
NAME_HELP = _("So you can tell your keys apart, like “My phone” or “Blue key”.")

FORMS = {
    "add_webauthn": "capy_auth.mfa.forms.AddPasskeyForm",
    "edit_webauthn": "capy_auth.mfa.forms.EditPasskeyForm",
}


class AddPasskeyForm(AddWebAuthnForm):
    name = forms.CharField(
        label=_("Name"), required=False, max_length=NAME_MAX_LENGTH, help_text=NAME_HELP
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        passwordless = self.fields.get("passwordless")  # only with passkey sign-in on
        if passwordless:
            passwordless.initial = True
            passwordless.label = _("Let it sign me in without my password")
            passwordless.help_text = _(
                "It then asks for your fingerprint, face or PIN. Untick this only for an "
                "older security key that has none of those: it then works only after "
                "your password."
            )


class EditPasskeyForm(EditWebAuthnForm):
    name = forms.CharField(label=_("Name"), max_length=NAME_MAX_LENGTH, help_text=NAME_HELP)
