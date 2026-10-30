"""Render each refs.bib entry's DOI in the bibliography.

IEEEtran.bst (1.14) ignores the ``doi`` field, so this adds a ``note`` that
prints it, built from the entry's own ``doi`` value (nothing is retyped).
Entries that already have a note, and arXiv entries (whose identifier is
already printed via ``howpublished``), are left alone. Idempotent.

    .venv/Scripts/python.exe paper/data/add_doi_notes.py
"""

from __future__ import annotations

import re
from pathlib import Path

BIB = Path(__file__).resolve().parents[1] / "refs.bib"


def main() -> None:
    text = BIB.read_text(encoding="utf-8")
    entries = re.split(r"(?=^@)", text, flags=re.M)
    added = 0
    out = []
    for entry in entries:
        doi = re.search(r"^[ \t]*doi\s*=\s*\{([^}]*)\}", entry, flags=re.M)
        if (
            doi
            and not re.search(r"^\s*note\s*=", entry, flags=re.M)
            and not doi.group(1).startswith("10.48550/arXiv")
        ):
            value = doi.group(1)
            note = (
                f"  note      = {{doi: \\href{{https://doi.org/{value}}}"
                f"{{\\nolinkurl{{{value}}}}}}},\n"
            )
            # insert the note as its own line just before the doi line
            entry = entry[: doi.start()] + note + entry[doi.start():]
            added += 1
        out.append(entry)
    BIB.write_text("".join(out), encoding="utf-8")
    print(f"added {added} DOI notes to {BIB}")


if __name__ == "__main__":
    main()
