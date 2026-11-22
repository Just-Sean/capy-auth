"""A copy of capy-project v1.1.0's user model (accounts/models.py), used when the tests
run with TEST_USER_MODEL=email, so the module is tested with the user a capy project
really has, not only Django's default."""

import uuid

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.db.models.functions import Lower


class User(AbstractUser):
    """Django's standard user, with email required, unique regardless of letter case
    and stored lowercase, plus a random public_id for URLs and APIs."""

    email = models.EmailField("email address")
    public_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(Lower("email"), name="email_users_user_email_ci_unique"),
        ]

    def save(self, *args, **kwargs):
        self.email = self.email.strip().lower()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.email
