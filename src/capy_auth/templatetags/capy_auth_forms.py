"""Renders a form field's input with the daisyUI class for its kind, so allauth's forms
look like the rest of a site styled with capy-theme."""

from django import template

register = template.Library()

# daisyUI's class for each kind of input (Django's widget_type); any other kind is a
# text-like input.
WIDGET_CLASSES = {
    "checkbox": "checkbox",
    "radio": "radio",
    "select": "select w-full",
    "textarea": "textarea w-full",
}
TEXT_INPUT_CLASS = "input w-full"


@register.filter
def daisy_widget(field):
    """The field's input, with daisyUI's class added to any class it already has."""
    widget_class = WIDGET_CLASSES.get(field.widget_type, TEXT_INPUT_CLASS)
    existing = field.field.widget.attrs.get("class", "")
    return field.as_widget(attrs={"class": f"{existing} {widget_class}".strip()})
