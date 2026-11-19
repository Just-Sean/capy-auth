from django.apps import AppConfig
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
        from capy_auth.sessions.checks import check_user_sessions

        checks.register(check_account_adapter)
        checks.register(check_starting_values)
        checks.register(check_security_settings)
        checks.register(check_email_queue)
        checks.register(check_breached_password_validator)
        checks.register(check_email_can_be_sent)
        checks.register(check_signup_form)
        checks.register(check_user_sessions)
        ban_receivers.connect_receivers()
        account_receivers.connect_receivers()
