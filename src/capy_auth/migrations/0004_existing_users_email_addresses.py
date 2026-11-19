"""Gives every existing user with an email, and no address in allauth's list yet, that
email as an unconfirmed primary address, so they confirm it with a code at their next
login (manage.py mark_email_verified confirms one by hand). A data migration on its
own, in batches of 1,000, each in its own short transaction, so no long transaction
holds locks while it runs."""

import logging

from django.conf import settings
from django.db import migrations, transaction

BATCH_SIZE = 1000
logger = logging.getLogger("capy_auth")


def add_missing_addresses(apps, schema_editor):
    field = getattr(settings, "ACCOUNT_USER_MODEL_EMAIL_FIELD", "email")
    if not field:
        return
    database = schema_editor.connection.alias
    user_model = apps.get_model(settings.AUTH_USER_MODEL)
    email_address = apps.get_model("account", "EmailAddress")
    max_length = email_address._meta.get_field("email").max_length
    users = (
        user_model.objects.using(database)
        .filter(emailaddress__isnull=True)
        .exclude(**{f"{field}__isnull": True})
        .exclude(**{field: ""})
        .order_by("pk")
        .values_list("pk", field)
    )
    too_long = 0
    batch = list(users[:BATCH_SIZE])
    while batch:
        addresses = []
        for pk, email in batch:
            email = email.strip().lower()
            if len(email) > max_length:
                too_long += 1
            elif email:  # an email of only spaces has no address
                addresses.append(
                    email_address(user_id=pk, email=email, primary=True, verified=False)
                )
        with transaction.atomic(using=database):
            email_address.objects.using(database).bulk_create(addresses)
        batch = list(users.filter(pk__gt=batch[-1][0])[:BATCH_SIZE])
    if too_long:
        logger.warning(
            "%s users' emails are longer than allauth allows (%s characters), so they "
            "weren't added; fix them in the admin.",
            too_long,
            max_length,
        )


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
