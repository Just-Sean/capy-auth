"""Renders a form field's input with classes the template chooses, so allauth's forms get
daisyUI's look. The class names stay in the templates (capy_auth/fields/widget.html),
where the project's Tailwind build finds them."""

from django import template

register = template.Library()


@register.filter
def daisy_widget(field, css_classes):
    """The field's input, with the given classes added to any class it already has."""
    existing = field.field.widget.attrs.get("class", "")
    return field.as_widget(attrs={"class": f"{existing} {css_classes}".strip()})


@register.filter
def is_app_code(field):
    """Whether a "code" field takes a code from an authenticator app or a recovery code
    (allauth's MFA forms), rather than a code from an email (its account forms)."""
    return type(field.form).__module__.startswith("allauth.mfa")


@register.filter
def daisy_code_widget(field, css_classes):
    """A code field: the given classes (and the error look), its hint (fields.html)
    linked like help text, and no autocorrect or spellcheck. An email code has letters,
    so phones shouldn't change their case; an app or recovery code is digits, so phones
    show a number pad."""
    described_by = [f"{field.auto_id}_hint"]
    if field.errors:
        described_by.append(f"{field.auto_id}_error")
        css_classes = f"{css_classes} input-error"
    attrs = {
        "class": css_classes,
        "autocorrect": "off",
        "spellcheck": "false",
        "aria-describedby": " ".join(described_by),
    }
    if is_app_code(field):
        attrs["inputmode"] = "numeric"
    else:
        attrs["autocapitalize"] = "characters"
    return field.as_widget(attrs=attrs)


@register.filter
def in_fours(text):
    """A long key in groups of 4 ("MGD5 S22E …"), easier to read and type; apps and
    allauth ignore the spaces."""
    return " ".join(text[i : i + 4] for i in range(0, len(text), 4))
