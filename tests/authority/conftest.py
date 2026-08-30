"""Shared fixtures for authority module tests -- the ADR-0019 two-authority split."""

from __future__ import annotations

import datetime

import pytest
from authority.issuance import AttributeAuthority, generate_authority


@pytest.fixture
def authority_med() -> AttributeAuthority:
    """Owns ``role:*`` (ADR-0019)."""
    return generate_authority("authority-med", frozenset({"role"}))


@pytest.fixture
def authority_net() -> AttributeAuthority:
    """Owns ``specialty:*``, ``facility:*``, ``owner:*`` -- home authority."""
    return generate_authority(
        "authority-net", frozenset({"specialty", "facility", "owner"})
    )


@pytest.fixture
def valid_window() -> tuple[datetime.datetime, datetime.datetime]:
    now = datetime.datetime.now(datetime.timezone.utc)
    return now - datetime.timedelta(days=1), now + datetime.timedelta(days=365)
