"""Federated record discovery (C13).

Discovery returns only record identifiers for a patient. It does not expose
encrypted record contents or cryptographic material.

Deliberately a projection over ``record_id``, not ``SELECT *``: P2-4's done-when
requires that discovery "learn nothing about contents." Returning ``Record``
objects here would hand the querying facility the ciphertext, nonce, and aad --
exactly what ARCHITECTURE §5 forbids for the discovery path. A caller with
legitimate access fetches the full record via ``storage.repositories.get_record``.
"""

from __future__ import annotations

import psycopg


def find_record_ids_by_patient(
    conn: psycopg.Connection,
    patient_id: str,
) -> list[str]:
    """Return record IDs belonging to a patient."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT record_id FROM records WHERE patient_id = %s",
            (patient_id,),
        )
        rows = cur.fetchall()

    return [row[0] for row in rows]
