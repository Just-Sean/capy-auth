from django.apps import AppConfig


class CapyAuthConfig(AppConfig):
    name = "capy_auth"
    label = "capy_auth"
    verbose_name = "Capy Auth"
    # Set here, not left to the project, so the module's migrations are the
    # same in every project whatever its DEFAULT_AUTO_FIELD.
    default_auto_field = "django.db.models.BigAutoField"
