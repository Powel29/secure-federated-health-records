"""Small presentation helpers for care episodes and record provenance."""

from __future__ import annotations

import hashlib
import unicodedata
from difflib import SequenceMatcher, get_close_matches
from typing import Any


def digest(text: str) -> str:
    """Same UTF-8 commitment used by the custodian; no secret is handled here."""
    return hashlib.sha256(text.strip().encode("utf-8")).hexdigest()


def normalized_name(text: str) -> str:
    return " ".join(
        "".join(
            c
            for c in unicodedata.normalize("NFKD", text.casefold())
            if not unicodedata.combining(c)
        )
        .replace("-", " ")
        .replace("'", "")
        .split()
    )


def name_matches(query: str, candidate: str) -> bool:
    """Suggestions only. A fuzzy match never selects or authorizes a patient."""
    query, candidate = normalized_name(query), normalized_name(candidate)
    return bool(
        query
        and candidate
        and (
            query == candidate or SequenceMatcher(None, query, candidate).ratio() >= 0.8
        )
    )


# Spelling variants and true synonyms only, never drug classes: a token matches
# a term exactly as indexed, so a query asks for every spelling (ADR-0061).
_SYNONYMS = [
    {"haemorrhage", "hemorrhage", "bleeding"},
    {"anaesthesia", "anesthesia"},
    {"oedema", "edema"},
    {"anaemia", "anemia"},
    {"penicillin", "penicillins"},
    {"anaphylaxis", "anaphylactic"},
    {"stemi", "infarction", "myocardial infarction", "heart attack"},
    {"diabetes", "diabetic"},
    {"anticoagulant", "anticoagulation"},
    {"seizure", "seizures", "epilepsy"},
]
SEARCH_VOCABULARY = sorted(
    {term for group in _SYNONYMS for term in group}
    | {"allergy", "aspirin", "troponin", "cardiac", "insulin", "metformin"}
    | {"glucose", "endocrinology", "trauma", "emergency", "fracture"}
    | {"resuscitation", "warfarin", "heparin", "pregnancy", "asthma"}
)


def expand_search_terms(term: str) -> list[str]:
    """The typed term, its closest vocabulary spelling, and that spelling's synonyms."""
    typed = " ".join(term.casefold().split())
    if not typed:
        return []
    close = get_close_matches(typed, SEARCH_VOCABULARY, n=1, cutoff=0.85)
    base = close[0] if close else typed
    group = next((g for g in _SYNONYMS if base in g), {base})
    return sorted({typed, base, *group})


def record_label(record: dict[str, Any]) -> str:
    clinical = record.get("clinical") or {}
    return " · ".join(
        str(v)
        for v in [
            clinical.get("title", "Legacy record (title unknown)"),
            clinical.get("record_type", "type unknown"),
            clinical.get("clinical_date", "date unknown"),
            clinical.get("author_id", "author unknown"),
            clinical.get("source", "source unknown"),
            record.get("facility_name") or record.get("facility_id"),
            record["record_id"],
        ]
        if v
    )


def episode_groups(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group the discovered snapshot; unknown episodes are never guessed."""
    groups: dict[str, dict[str, Any]] = {}
    for record in records:
        clinical = record.get("clinical") or {}
        key = clinical.get("episode_id") or record["record_id"]
        group = groups.setdefault(key, {"key": key, "records": [], "label": key})
        group["records"].append({**record, "label": record_label(record)})
    return list(groups.values())
