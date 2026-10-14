"""Display-only template filters, loaded as builtins for every portal template."""

from __future__ import annotations

from django import template

register = template.Library()


@register.filter
def humanize_code(value: object) -> str:
    """Readable label for an enum code: ``cardiac_arrest`` -> ``Cardiac arrest``."""
    text = str(value or "").replace("_", " ").replace("-", " ").strip()
    return text[:1].upper() + text[1:]
