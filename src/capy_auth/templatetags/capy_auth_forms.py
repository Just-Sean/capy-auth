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
def daisy_code_widget(field, css_classes):
    """A code from an email: the given classes, no autocorrect or spellcheck (phones
    would change the letters), and its hint (fields.html) linked like help text."""
    described_by = [f"{field.auto_id}_hint"]
    if field.errors:
        described_by.append(f"{field.auto_id}_error")
    return field.as_widget(
        attrs={
            "class": css_classes,
            "autocapitalize": "characters",
            "autocorrect": "off",
            "spellcheck": "false",
            "aria-describedby": " ".join(described_by),
        }
    )
