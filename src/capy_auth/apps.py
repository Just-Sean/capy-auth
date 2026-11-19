from django.apps import AppConfig, apps
from django.core import checks


class CapyAuthConfig(AppConfig):
    name = "capy_auth"
    label = "capy_auth"
    verbose_name = "Capy Auth"
    # Set here, not left to the project, so the module's migrations are the
    # same in every project whatever its DEFAULT_AUTO_FIELD.
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self):
        from capy_auth.account import receivers as account_receivers
        from capy_auth.bans import receivers as ban_receivers
        from capy_auth.bans.checks import check_signup_form
        from capy_auth.config.checks import (
            check_account_adapter,
            check_breached_password_validator,
            check_email_queue,
            check_security_settings,
            check_starting_values,
        )
        from capy_auth.limits.checks import check_email_can_be_sent
        from capy_auth.mfa.checks import check_encryption_keys, check_mfa_setup
        from capy_auth.sessions.checks import check_session_store, check_user_sessions

        checks.register(check_account_adapter)
        checks.register(check_starting_values)
        checks.register(check_security_settings)
        checks.register(check_email_queue)
        checks.register(check_breached_password_validator)
        checks.register(check_email_can_be_sent)
        checks.register(check_signup_form)
        checks.register(check_user_sessions)
        checks.register(check_session_store)
        checks.register(check_mfa_setup)
        checks.register(check_encryption_keys)
        ban_receivers.connect_receivers()
        account_receivers.connect_receivers()
        if apps.is_installed("allauth.usersessions"):  # E006 reports it missing
            from django.contrib.auth.signals import user_logged_in

            from capy_auth.sessions.recording import record_django_login

            user_logged_in.connect(record_django_login, dispatch_uid="capy_auth_record_login")
