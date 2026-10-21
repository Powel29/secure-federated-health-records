"""Inline every \\input{...} / \\include{...} so the paper builds as one file.

The compile_latex tool accepts a single self-contained document, and its TeX
Live has no IEEEtran class or bibliography style. ``--embed`` writes such
support files into the document as ``filecontents*`` blocks ahead of
``\\documentclass``, so LaTeX and BibTeX find them at build time. Embedded
files are minified to stay under the tool's 300 KB limit: comment text and
leading blanks go, but a trailing ``%`` itself is kept, since it is
significant in a class file.

Paths are resolved relative to the including file; a missing file is an
error, not a silent gap.

    python .claude/skills/ieee-paper/scripts/flatten_tex.py paper/main.tex paper/build/main-flat.tex \\
        --embed paper/IEEEtran.cls paper/IEEEtran.bst
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

_INPUT = re.compile(r"^(?P<pre>[^%\n]*?)\\(?:input|include)\{(?P<name>[^}]+)\}", re.M)
_COMMENT_LINE = re.compile(r"^[ \t]*%.*\n", re.M)
_LIMIT_BYTES = 300_000


def flatten(path: Path, seen: tuple[Path, ...] = ()) -> str:
    path = path.resolve()
    if path in seen:
        raise SystemExit(f"circular \\input: {path}")
    text = path.read_text(encoding="utf-8")

    def inline(match: re.Match[str]) -> str:
        target = (path.parent / match["name"]).with_suffix(".tex")
        if not target.exists():
            raise SystemExit(f"{path}: \\input target not found: {target}")
        return match["pre"] + flatten(target, (*seen, path))

    return _INPUT.sub(inline, text)


def _strip_tex_comment(line: str) -> str:
    # Keep the first unescaped % (it suppresses the end-of-line space) and
    # drop the comment text after it; leading blanks are ignored by TeX anyway.
    i = 0
    while i < len(line):
        if line[i] == "\\":
            i += 2
            continue
        if line[i] == "%":
            line = line[: i + 1]
            break
        i += 1
    return line.lstrip(" \t")


def _minify(path: Path, text: str) -> str:
    if path.suffix == ".bst":
        # BibTeX style: % starts a comment anywhere; whitespace is insignificant.
        lines = (re.sub(r"%.*", "", line).strip() for line in text.split("\n"))
        return "\n".join(line for line in lines if line)
    text = _COMMENT_LINE.sub("", text)
    return "\n".join(_strip_tex_comment(line) for line in text.split("\n"))


def embed(path: Path) -> str:
    if not path.exists():
        raise SystemExit(f"--embed file not found: {path}")
    body = _minify(path, path.read_text(encoding="latin-1"))
    if "\\end{filecontents*}" in body:
        raise SystemExit(f"{path} cannot be embedded: contains \\end{{filecontents*}}")
    return (
        f"\\begin{{filecontents*}}[overwrite]{{{path.name}}}\n"
        f"{body.rstrip()}\n\\end{{filecontents*}}\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("main", type=Path)
    parser.add_argument("out", type=Path)
    parser.add_argument("--embed", type=Path, nargs="*", default=[])
    args = parser.parse_args()

    text = "".join(embed(p) for p in args.embed) + flatten(args.main)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(text, encoding="utf-8")
    size = args.out.stat().st_size
    print(f"wrote {args.out} ({size} bytes)")
    if size > _LIMIT_BYTES:
        raise SystemExit(f"{size} bytes exceeds the compile tool's {_LIMIT_BYTES}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
