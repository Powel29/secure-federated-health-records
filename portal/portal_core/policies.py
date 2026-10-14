"""Clinical access-policy presets a patient can choose when uploading.

Each preset is the *clinical branch* of a record's policy tree in the
``contracts.policy.PolicyTree`` wire shape (ADR-0002 / ARCHITECTURE §3). The
facility's ingest path adds the ``owner:<patient_id>`` OR-leaf itself
(ADR-0016), so every uploaded record is readable by its owner regardless of
the preset. The portal only *chooses* a tree; compiling it into a Shamir
layout and sealing the DEK happen at the facility.

Attribute namespaces follow ADR-0019: ``role`` is issued by ``authority-med``,
``specialty`` (and ``owner``) by ``authority-net``.
"""

from __future__ import annotations

from typing import Any


def _leaf(authority_id: str, name: str, value: str) -> dict[str, Any]:
    return {
        "node_type": "leaf",
        "attribute": {"name": name, "value": value},
        "authority_id": authority_id,
    }


def _and(*children: dict[str, Any]) -> dict[str, Any]:
    return {"node_type": "and", "children": list(children)}


PHYSICIAN = _leaf("authority-med", "role", "physician")

POLICY_PRESETS: dict[str, dict[str, Any]] = {
    "cardiology": {
        "label": "Cardiology — physician AND specialty:cardiology",
        "tree": _and(PHYSICIAN, _leaf("authority-net", "specialty", "cardiology")),
    },
    "endocrinology": {
        "label": "Endocrinology — physician AND specialty:endocrinology",
        "tree": _and(PHYSICIAN, _leaf("authority-net", "specialty", "endocrinology")),
    },
    "emergency": {
        "label": "Emergency medicine — physician AND role:emergency-physician",
        "tree": _and(PHYSICIAN, _leaf("authority-med", "role", "emergency-physician")),
    },
    "general": {
        "label": "Treating physician or ED physician — patient-signed consent required",
        "tree": {
            "node_type": "or",
            "children": [
                PHYSICIAN,
                _leaf("authority-med", "role", "emergency-physician"),
            ],
        },
    },
}


def preset_choices() -> list[tuple[str, str]]:
    return [(key, value["label"]) for key, value in POLICY_PRESETS.items()]


def policy_for(key: str) -> dict[str, Any] | None:
    preset = POLICY_PRESETS.get(key)
    return preset["tree"] if preset else None
