"""Gives every existing user with an email, and no address in allauth's list yet, that
email as an unconfirmed primary address, so they confirm it with a code at their next
login (manage.py mark_email_verified confirms one by hand). A data migration on its
own, in batches, so no transaction holds the users table for long."""

from django.conf import settings
from django.db import migrations, transaction

BATCH_SIZE = 1000


def add_missing_addresses(apps, schema_editor):
    field = getattr(settings, "ACCOUNT_USER_MODEL_EMAIL_FIELD", "email")
    if not field:
        return
    database = schema_editor.connection.alias
    user_model = apps.get_model(settings.AUTH_USER_MODEL)
    email_address = apps.get_model("account", "EmailAddress")
    users = (
        user_model.objects.using(database)
        .filter(emailaddress__isnull=True)
        .exclude(**{f"{field}__isnull": True})
        .exclude(**{field: ""})
        .order_by("pk")
        .values_list("pk", field)
    )
    after = None
    while batch := list((users if after is None else users.filter(pk__gt=after))[:BATCH_SIZE]):
        addresses = [
            email_address(user_id=pk, email=email.strip().lower(), primary=True, verified=False)
            for pk, email in batch
        ]
        with transaction.atomic(using=database):
            email_address.objects.using(database).bulk_create(addresses, ignore_conflicts=True)
        after = batch[-1][0]


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("capy_auth", "0003_ban_list"),
        ("account", "0009_emailaddress_unique_primary_email"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.RunPython(add_missing_addresses, migrations.RunPython.noop),
    ]
