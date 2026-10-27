"""Look for canaries in transcripts, caches and output files. It never prints a value.

It reads raw bytes (without parsing the format, which is internal to Claude Code and changes between
versions) and looks for every canary in its usual forms: as-is, normalized and JSON-escaped. Inside
.xlsx/.ods files it also looks into every unzipped part.

Usage: python canaries/audit.py <manifest.json> [paths...]
Without paths it audits ~/.claude/projects, file-history, paste-cache and history.jsonl.
Exits with code 1 if it finds any canary.
"""

from __future__ import annotations

import argparse
import json
import sys
import unicodedata
import zipfile
from collections.abc import Iterator
from pathlib import Path

DEFAULT_PATHS = [
    Path.home() / ".claude" / "projects",
    Path.home() / ".claude" / "file-history",
    Path.home() / ".claude" / "paste-cache",
    Path.home() / ".claude" / "history.jsonl",
]
ZIPS = {".xlsx", ".xlsm", ".ods", ".docx", ".zip"}


def _without_accents(text: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFKD", text) if not unicodedata.combining(c))


def forms(value: str) -> set[bytes]:
    variants = {value, value.lower(), _without_accents(value), _without_accents(value).lower()}
    if value.replace(".", "").isdigit():
        variants.add(value.replace(".", ""))
    result: set[bytes] = set()
    for v in variants:
        result.add(v.encode("utf-8"))
        result.add(json.dumps(v).strip('"').encode("ascii"))  # "á" inside JSON
        try:
            result.add(v.encode("latin-1"))
        except UnicodeEncodeError:
            pass
    return {r for r in result if len(r) >= 6}


def _contents(path: Path) -> Iterator[tuple[str, bytes]]:
    data = path.read_bytes()
    yield str(path), data
    if path.suffix.lower() in ZIPS and zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as package:
            for part in package.namelist():
                yield f"{path}!{part}", package.read(part)


def _files(paths: list[Path]) -> Iterator[Path]:
    for path in paths:
        if path.is_file():
            yield path
        elif path.is_dir():
            yield from (p for p in path.rglob("*") if p.is_file() and not p.is_symlink())


def audit(manifest: Path, paths: list[Path]) -> dict[str, int]:
    values = json.loads(manifest.read_text())["values"]
    patterns = [forms(v) for v in values]
    findings: dict[str, int] = {}
    for path in _files(paths):
        if path.resolve() == manifest.resolve():
            continue
        try:
            for where, data in _contents(path):
                n = sum(1 for p in patterns if any(f in data for f in p))
                if n:
                    findings[where] = findings.get(where, 0) + n
        except (OSError, zipfile.BadZipFile):
            continue
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("manifest", type=Path)
    parser.add_argument("paths", type=Path, nargs="*")
    args = parser.parse_args()

    findings = audit(args.manifest, args.paths or DEFAULT_PATHS)
    if not findings:
        print("0 canaries found")
        return
    print(f"{sum(findings.values())} canaries found in {len(findings)} places:")
    for where, n in sorted(findings.items()):
        print(f"  {n:5d}  {where}")
    sys.exit(1)


if __name__ == "__main__":
    main()
