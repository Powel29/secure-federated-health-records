"""Clinical provenance and disclosure labels, separate from encrypted content."""

from __future__ import annotations

import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from contracts.base import B64Bytes

# The furthest-ahead time zone is UTC+14, so no date later than this is
# "today" anywhere; a clinic in UTC+5:30 can still file today's record before
# 05:30 local time.
_FURTHEST_UTC_OFFSET = datetime.timedelta(hours=14)


def latest_local_date() -> datetime.date:
    """The latest calendar date that is today somewhere on Earth."""
    return (datetime.datetime.now(datetime.timezone.utc) + _FURTHEST_UTC_OFFSET).date()


class ClinicalMetadata(BaseModel):
    """Explicit provenance; missing legacy information is unknown, never inferred."""

    model_config = ConfigDict(extra="forbid")
    title: str = Field(default="Untitled legacy record", max_length=200)
    author_id: str = Field(default="unknown", max_length=128)
    clinical_date: datetime.date | None = None
    record_type: str = Field(default="unknown", max_length=64)
    episode_id: str = Field(default="", max_length=128)
    source: Literal["hospital", "patient_upload", "clinician_note", "unknown"] = (
        "unknown"
    )
    sensitivity: Literal[
        "general", "mental_health", "hiv", "substance_use", "restricted"
    ] = "general"
    care_team_consent: bool = False
    # The patient's signature over every field above, bound to the record and
    # patient ids, and the patient certificate it verifies against (ADR-0064).
    # Unsigned or unverifiable labels are treated as the strictest.
    signature: B64Bytes | None = None
    signer_certificate_pem: str | None = Field(default=None, max_length=8192)

    @field_validator("clinical_date")
    @classmethod
    def no_future_clinical_date(
        cls, value: datetime.date | None
    ) -> datetime.date | None:
        """Clinical events cannot be recorded as having occurred in the future."""
        if value and value > latest_local_date():
            raise ValueError("clinical_date cannot be in the future")
        return value
