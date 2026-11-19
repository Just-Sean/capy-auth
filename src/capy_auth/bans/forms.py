"""The ban check at signup. allauth builds its signup forms (the website's, the API's
and social signup's) on the form a project names in ACCOUNT_SIGNUP_FORM_CLASS, so a
project points that setting here (see the README); capy_auth.E005 stops a site that
doesn't. A project with its own signup form bases it on BanCheck."""

from django import forms

from .selectors import is_banned_email


class BanCheck(forms.Form):
    def clean(self):
        """A banned address is treated as one that already has an account: allauth
        shows the usual "enter the code" page, creates nothing and sends the "already
        has an account" email, which capy-auth replaces with the ban notice. So the
        page never shows that the address is banned; only its owner learns that."""
        cleaned_data = super().clean()
        if is_banned_email(cleaned_data.get("email")):
            self.account_already_exists = True
        return cleaned_data

    def signup(self, request, user):
        """allauth calls this after creating an account; there's nothing extra to save."""
