"""Clinical provenance and disclosure labels, separate from encrypted content."""

from __future__ import annotations

import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


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

    @field_validator("clinical_date")
    @classmethod
    def no_future_clinical_date(
        cls, value: datetime.date | None
    ) -> datetime.date | None:
        """Clinical events cannot be recorded as having occurred in the future."""
        if value and value > datetime.datetime.now(datetime.timezone.utc).date():
            raise ValueError("clinical_date cannot be in the future")
        return value
