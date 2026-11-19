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
        from capy_auth.config.checks import (
            check_account_adapter,
            check_breached_password_validator,
            check_email_queue,
            check_security_settings,
            check_starting_values,
        )

        checks.register(check_account_adapter)
        checks.register(check_starting_values)
        checks.register(check_security_settings)
        checks.register(check_email_queue)
        checks.register(check_breached_password_validator)
