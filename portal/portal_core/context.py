"""Template context shared by every portal page."""

from __future__ import annotations

from typing import Any

from django.conf import settings


def product(request: Any) -> dict[str, Any]:
    return {"product_name": settings.PRODUCT_NAME}
