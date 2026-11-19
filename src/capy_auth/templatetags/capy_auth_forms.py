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
